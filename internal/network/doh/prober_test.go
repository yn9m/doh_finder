package doh

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"doh-finder/internal/pkg/ds"
	"github.com/miekg/dns"
)

func TestProberPinnedIPv4AndDNSValidation(t *testing.T) {
	for _, test := range []struct{ mode, want string }{
		{"success", "SUCCESS"}, {"cname", "SUCCESS"}, {"servfail", "SERVFAIL"},
		{"nxdomain", "NXDOMAIN"}, {"refused", "REFUSED"}, {"empty", "NO_ANSWER"},
		{"unrelated", "NO_ANSWER"}, {"http", "HTTP_ERROR"}, {"malformed", "ERROR"},
		{"bad-cert", "TLS_ERROR"}, {"bad-pin", "TLS_ERROR"}, {"timeout", "TIMEOUT"},
	} {
		t.Run(test.mode, func(t *testing.T) {
			var requests atomic.Int32
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if r.TLS.ServerName != "example.com" {
					t.Errorf("wrong SNI: %s", r.TLS.ServerName)
				}
				if r.URL.Path != "/dns-query" || !strings.HasPrefix(r.Host, "example.com:") {
					t.Errorf("wrong endpoint: %s %s", r.Host, r.URL)
				}
				if test.mode == "http" {
					w.WriteHeader(503)
					return
				}
				if test.mode == "malformed" {
					fmt.Fprint(w, "not DNS")
					return
				}
				if test.mode == "timeout" {
					<-r.Context().Done()
					return
				}
				wire, err := base64.RawURLEncoding.DecodeString(r.URL.Query().Get("dns"))
				if err != nil {
					t.Error(err)
					return
				}
				request := new(dns.Msg)
				if err := request.Unpack(wire); err != nil {
					t.Error(err)
					return
				}
				if len(request.Question) != 1 || request.Question[0].Qtype != dns.TypeA {
					t.Errorf("not an A query: %v", request)
					return
				}
				reply := new(dns.Msg)
				reply.SetReply(request)
				name := request.Question[0].Name
				switch test.mode {
				case "servfail":
					reply.Rcode = dns.RcodeServerFailure
				case "nxdomain":
					reply.Rcode = dns.RcodeNameError
				case "refused":
					reply.Rcode = dns.RcodeRefused
				case "empty":
				default:
					if test.mode == "cname" {
						reply.Answer = append(reply.Answer, &dns.CNAME{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 30}, Target: "alias.example."})
						name = "alias.example."
					}
					if test.mode == "unrelated" {
						name = "unrelated.example."
					}
					reply.Answer = append(reply.Answer, &dns.A{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30}, A: net.ParseIP("93.184.216.34")})
				}
				body, err := reply.Pack()
				if err != nil {
					t.Error(err)
					return
				}
				w.Header().Set("Content-Type", "application/dns-message")
				w.Write(body)
			}))
			server.EnableHTTP2 = true
			server.Config.ErrorLog = log.New(io.Discard, "", 0)
			server.StartTLS()
			defer server.Close()
			ip := "127.0.0.1"
			resolver := ds.Resolver{Name: "local", IP: &ip, DoHURL: strings.Replace(server.URL, "127.0.0.1", "example.com", 1) + "/dns-query"}
			p := NewProber(time.Second, []string{"example.com"}, slog.New(slog.NewTextHandler(io.Discard, nil)))
			if test.mode != "bad-cert" {
				p.rootCAs = x509.NewCertPool()
				p.rootCAs.AddCert(server.Certificate())
			}
			pin := sha256.Sum256(server.Certificate().RawTBSCertificate)
			resolver.Hashes = []string{hex.EncodeToString(pin[:])}
			if test.mode == "bad-pin" {
				resolver.Hashes = []string{strings.Repeat("00", 32)}
			}
			if test.mode == "timeout" {
				p.timeout = 50 * time.Millisecond
			}
			result := p.Check(context.Background(), resolver)
			if result.TCP.Status != "SUCCESS" {
				t.Fatalf("TCP: %+v", result.TCP)
			}
			if len(result.DNS) != 1 || result.DNS[0].Status != test.want {
				t.Fatalf("want %s, got %+v", test.want, result.DNS)
			}
			if result.Success != (test.want == "SUCCESS") {
				t.Fatalf("wrong overall success: %+v", result)
			}
			if test.want == "SUCCESS" {
				if requests.Load() != 1 || result.DNS[0].TLSVersion == "" || len(result.DNS[0].Addresses) != 1 {
					t.Fatalf("missing verified result data: %+v", result)
				}
			}
		})
	}
}

func TestProberRejectsNonIPv4BeforeNetworking(t *testing.T) {
	ipv6, ipv4 := "::1", "127.0.0.1"
	for _, resolver := range []ds.Resolver{
		{DoHURL: "https://example.com/dns-query"},
		{IP: &ipv6, DoHURL: "https://example.com/dns-query"},
		{IP: &ipv4, DoHURL: "https://[::1]/dns-query"},
		{IP: &ipv4, DoHURL: "https://192.0.2.1/dns-query"},
		{IP: &ipv4, DoHURL: "http://example.com/dns-query"},
		{IP: &ipv4, DoHURL: "https://example.com/dns-query?profile=a"},
	} {
		p := NewProber(time.Second, []string{"example.com"}, slog.Default())
		if got := p.Check(context.Background(), resolver); got.TCP.Status != "INVALID_CONFIG" || got.Success {
			t.Fatalf("invalid configuration accepted: %+v", got)
		}
	}
}
