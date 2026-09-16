package doh

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"doh-finder/internal/pkg/ds"
	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/miekg/dns"
)

type Prober struct {
	timeout time.Duration
	domains []string
	logger  *slog.Logger
	rootCAs *x509.CertPool
}

func NewProber(timeout time.Duration, domains []string, logger *slog.Logger) *Prober {
	return &Prober{timeout: timeout, domains: append([]string(nil), domains...), logger: logger}
}

func (p *Prober) Check(ctx context.Context, resolver ds.Resolver) ds.ServerResult {
	result := ds.ServerResult{Name: resolver.Name, DoHURL: resolver.DoHURL, DNS: make([]ds.DNSResult, 0, len(p.domains))}
	if resolver.IP != nil {
		result.IP = *resolver.IP
	}
	ip, port, err := endpoint(resolver)
	if err != nil {
		result.TCP = ds.ProbeResult{Status: "INVALID_CONFIG", Error: err.Error()}
		for _, domain := range p.domains {
			result.DNS = append(result.DNS, ds.DNSResult{ProbeResult: result.TCP, Domain: domain, Addresses: []string{}})
		}
		return result
	}
	// TCP reachability and DoH are independent observations. A TCP failure
	// doesn't suppress DNS queries, and a TCP success doesn't imply DNS success.
	var tcp sync.WaitGroup
	tcp.Add(1)
	go func() {
		defer tcp.Done()
		start := time.Now()
		dialer := net.Dialer{Timeout: p.timeout}
		conn, err := dialer.DialContext(ctx, "tcp4", net.JoinHostPort(ip.String(), port))
		if err == nil {
			err = conn.Close()
		}
		result.TCP = observation(start, err)
	}()
	for _, domain := range p.domains {
		result.DNS = append(result.DNS, p.query(ctx, resolver, ip, domain))
	}
	tcp.Wait()
	result.Success = result.TCP.Status == "SUCCESS" && len(result.DNS) > 0
	for _, query := range result.DNS {
		result.Success = result.Success && query.Status == "SUCCESS"
	}
	return result
}

func endpoint(resolver ds.Resolver) (netip.Addr, string, error) {
	if resolver.IP == nil {
		return netip.Addr{}, "", fmt.Errorf("an explicit IPv4 address is required")
	}
	ip, err := netip.ParseAddr(*resolver.IP)
	if err != nil || !ip.Is4() {
		return netip.Addr{}, "", fmt.Errorf("only explicit IPv4 addresses are supported")
	}
	u, err := url.Parse(resolver.DoHURL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
		return netip.Addr{}, "", fmt.Errorf("invalid HTTPS endpoint")
	}
	// This dnsproxy version replaces URL query parameters with its DNS query.
	// Reject such endpoints explicitly rather than test a different URL.
	if u.RawQuery != "" {
		return netip.Addr{}, "", fmt.Errorf("DoH URLs with query parameters are not supported by the current client")
	}
	if hostIP, err := netip.ParseAddr(u.Hostname()); err == nil && hostIP != ip {
		return netip.Addr{}, "", fmt.Errorf("literal URL IP must match the catalog IPv4")
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return netip.Addr{}, "", fmt.Errorf("invalid HTTPS port")
	}
	return ip, port, nil
}

func (p *Prober) query(ctx context.Context, resolver ds.Resolver, ip netip.Addr, domain string) ds.DNSResult {
	start := time.Now()
	result := ds.DNSResult{Domain: domain, Addresses: []string{}}
	if err := ctx.Err(); err != nil {
		result.ProbeResult = observation(start, err)
		return result
	}
	timeout := p.timeout
	if deadline, ok := ctx.Deadline(); ok {
		timeout = min(timeout, time.Until(deadline))
	}
	if timeout <= 0 {
		result.ProbeResult = observation(start, context.DeadlineExceeded)
		return result
	}

	var tlsMu sync.Mutex
	var tlsVersion, protocol string
	client, err := upstream.AddressToUpstream(resolver.DoHURL, &upstream.Options{
		Timeout: timeout, Logger: p.logger, RootCAs: p.rootCAs,
		// No system resolver, stamp bootstrap addresses, or IPv6 fallback.
		Bootstrap:    upstream.StaticResolver{ip},
		HTTPVersions: []upstream.HTTPVersion{upstream.HTTPVersion11, upstream.HTTPVersion2},
		VerifyConnection: func(state tls.ConnectionState) error {
			tlsMu.Lock()
			tlsVersion, protocol = tls.VersionName(state.Version), state.NegotiatedProtocol
			if protocol == "" {
				protocol = "http/1.1"
			}
			tlsMu.Unlock()
			return verifyHashes(state, resolver.Hashes)
		},
	})
	if err != nil {
		result.ProbeResult = observation(start, err)
		return result
	}
	// Exchange has no context argument. Its per-query timeout bounds shutdown;
	// we wait for it rather than leave detached network goroutines behind.
	request := new(dns.Msg)
	request.SetQuestion(dns.Fqdn(domain), dns.TypeA)
	response, err := client.Exchange(request)
	closeErr := client.Close()
	tlsMu.Lock()
	result.TLSVersion, result.Protocol = tlsVersion, protocol
	tlsMu.Unlock()
	if err == nil {
		err = closeErr
	}
	if ctx.Err() != nil {
		err = ctx.Err()
	}
	result.ProbeResult = observation(start, err)
	if err != nil {
		return result
	}
	if response == nil || !response.Response || response.Truncated || len(response.Question) != 1 ||
		!strings.EqualFold(response.Question[0].Name, request.Question[0].Name) ||
		response.Question[0].Qtype != dns.TypeA || response.Question[0].Qclass != dns.ClassINET {
		result.Status, result.Error = "INVALID_DNS_RESPONSE", "response does not match the A query"
		return result
	}
	if response.Rcode != dns.RcodeSuccess {
		result.Status = dns.RcodeToString[response.Rcode]
		if result.Status == "" {
			result.Status = fmt.Sprintf("RCODE_%d", response.Rcode)
		}
		result.Error = "DNS response: " + result.Status
		return result
	}
	result.Addresses = answerIPs(response, domain)
	if len(result.Addresses) == 0 {
		result.Status, result.Error = "NO_ANSWER", "no usable IPv4 answer for the queried domain"
	}
	return result
}

func answerIPs(response *dns.Msg, domain string) []string {
	name := dns.Fqdn(domain)
	seen := map[string]bool{}
	addresses := map[string]bool{}
	for range len(response.Answer) + 1 {
		key := strings.ToLower(name)
		if seen[key] {
			break
		}
		seen[key] = true
		next := ""
		for _, rr := range response.Answer {
			if !strings.EqualFold(rr.Header().Name, name) {
				continue
			}
			switch rr := rr.(type) {
			case *dns.A:
				if v4 := rr.A.To4(); v4 != nil && !v4.IsUnspecified() && !v4.IsLoopback() {
					addresses[v4.String()] = true
				}
			case *dns.CNAME:
				next = rr.Target
			}
		}
		if next == "" {
			break
		}
		name = next
	}
	result := make([]string, 0, len(addresses))
	for address := range addresses {
		result = append(result, address)
	}
	sort.Strings(result)
	return result
}

func verifyHashes(state tls.ConnectionState, hashes []string) error {
	if len(hashes) == 0 {
		return nil
	}
	for _, expected := range hashes {
		want, err := hex.DecodeString(expected)
		if err != nil || len(want) != sha256.Size {
			return fmt.Errorf("invalid certificate hash in catalog")
		}
		for _, cert := range state.PeerCertificates {
			got := sha256.Sum256(cert.RawTBSCertificate)
			if strings.EqualFold(hex.EncodeToString(got[:]), expected) {
				return nil
			}
		}
	}
	return fmt.Errorf("TLS certificate hash mismatch")
}

func observation(start time.Time, err error) ds.ProbeResult {
	result := ds.ProbeResult{Status: "SUCCESS", ElapsedMS: time.Since(start).Milliseconds()}
	if err == nil {
		return result
	}
	result.Error = err.Error()
	var netErr net.Error
	text := strings.ToLower(err.Error())
	switch {
	case errors.Is(err, context.Canceled):
		result.Status = "CANCELLED"
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &netErr) && netErr.Timeout():
		result.Status = "TIMEOUT"
	case strings.Contains(text, "refused"):
		result.Status = "CONNECTION_REFUSED"
	case strings.Contains(text, "reset"), strings.Contains(text, "forcibly closed"):
		result.Status = "RESET"
	case strings.Contains(text, "tls"), strings.Contains(text, "certificate"), strings.Contains(text, "x509"):
		result.Status = "TLS_ERROR"
	case strings.Contains(text, "expected status 200"):
		result.Status = "HTTP_ERROR"
	default:
		result.Status = "ERROR"
	}
	return result
}
