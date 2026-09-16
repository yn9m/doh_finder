package systemdns

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"time"
)

// Site traffic uses only addresses resolved by the Windows DNS client during this
// trial. No proxy, alternate resolver, redirects or IPv6 can mask a DNS failure.
func checkSite(ctx context.Context, domain string, addresses []string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	transport := &http.Transport{ForceAttemptHTTP2: true, DialContext: func(ctx context.Context, _, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil || host != domain {
			return nil, fmt.Errorf("unexpected verification host %q", address)
		}
		var lastErr error
		for _, ip := range addresses {
			parsed, err := netip.ParseAddr(ip)
			if err != nil || !parsed.Is4() || parsed.IsLoopback() || parsed.IsUnspecified() {
				continue
			}
			dialer := net.Dialer{Timeout: timeout}
			conn, err := dialer.DialContext(ctx, "tcp4", net.JoinHostPort(ip, port))
			if err == nil {
				return conn, nil
			}
			lastErr = err
		}
		return nil, fmt.Errorf("no reachable IPv4 for %s: %v", domain, lastErr)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+domain+"/", nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("HTTPS check for %s: %w", domain, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return fmt.Errorf("HTTPS check for %s: HTTP %d", domain, resp.StatusCode)
	}
	if _, err := io.Copy(io.Discard, io.LimitReader(resp.Body, 32<<10)); err != nil {
		return fmt.Errorf("read HTTPS response from %s: %w", domain, err)
	}
	return nil
}
