package dnscrypt

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

const exampleStamp = "sdns://AgcAAAAAAAAADTIxNy4xNjkuMjAuMjIADWRucy5hYS5uZXQudWsKL2Rucy1xdWVyeQ"
const secondStamp = "sdns://AgcAAAAAAAAADTIxNy4xNjkuMjAuMjMADWRucy5hYS5uZXQudWsKL2Rucy1xdWVyeQ"
const ipv6Stamp = "sdns://AgcAAAAAAAAAEFsyMDAxOjhiMDo6MjAyMl0ADWRucy5hYS5uZXQudWsKL2Rucy1xdWVyeQ"

func TestParseKeepsAllEndpointsAndUsesProtocol(t *testing.T) {
	body := "# public-resolvers\r\n## no-doh-in-name\r\n" + exampleStamp + "\r\n" + secondStamp +
		"\r\n## ipv6\r\n" + ipv6Stamp + "\r\n## misleading-doh-name\r\nsdns://AQ\r\n"
	got, err := parse([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d endpoints, want 3", len(got))
	}
	if got[0].Name != "no-doh-in-name" || got[1].Name != got[0].Name {
		t.Fatal("lost heading or multiple stamps")
	}
	if *got[0].IP != "217.169.20.22" || *got[1].IP != "217.169.20.23" || *got[2].IP != "2001:8b0::2022" {
		t.Fatalf("incorrect endpoint IPs: %+v", got)
	}
	if got[0].DoHURL != "https://dns.aa.net.uk/dns-query" || got[0].Stamp != exampleStamp {
		t.Fatalf("incorrect mapping: %+v", got[0])
	}
	if !got[0].Properties.DNSSEC || !got[0].Properties.NoLog || !got[0].Properties.NoFilter {
		t.Fatal("lost source property flags")
	}
}

// Construct wire bytes independently from the production decoder.
func fixtureStamp(address, authority, path string, extras bool) string {
	raw := []byte{2, 1, 0, 0, 0, 0, 0, 0, 0}
	lp := func(value string) { raw = append(raw, byte(len(value))); raw = append(raw, value...) }
	lp(address)
	if extras {
		raw = append(raw, 0x80|32)
		raw = append(raw, bytes.Repeat([]byte{0xab}, 32)...)
		raw = append(raw, 32)
		raw = append(raw, bytes.Repeat([]byte{0xcd}, 32)...)
	} else {
		raw = append(raw, 0)
	}
	lp(authority)
	lp(path)
	if extras {
		raw = append(raw, 0x80|7)
		raw = append(raw, "9.9.9.9"...)
		lp("[2620:fe::fe]")
	}
	return "sdns://" + base64.RawURLEncoding.EncodeToString(raw)
}

func TestParseMissingIPPortHashesAndBootstrap(t *testing.T) {
	stamp := fixtureStamp("", "resolver.example:8443", "/dns%2Dquery?profile=a", true)
	got, err := parse([]byte("## test\n" + stamp))
	if err != nil {
		t.Fatal(err)
	}
	r := got[0]
	if r.IP != nil || r.DoHURL != "https://resolver.example:8443/dns%2Dquery?profile=a" {
		t.Fatalf("wrong URL or fabricated IP: %+v", r)
	}
	if len(r.Hashes) != 2 || r.Hashes[0] != strings.Repeat("ab", 32) || r.Hashes[1] != strings.Repeat("cd", 32) {
		t.Fatalf("lost certificate hashes: %v", r.Hashes)
	}
	if len(r.BootstrapDNS) != 2 || r.BootstrapDNS[0] != "9.9.9.9" || r.BootstrapDNS[1] != "2620:fe::fe" {
		t.Fatalf("incorrect bootstrap resolvers: %v", r.BootstrapDNS)
	}
	if !r.Properties.DNSSEC || r.Properties.NoLog || r.Properties.NoFilter {
		t.Fatal("incorrect property bits")
	}
}

func TestParseRejectsInvalidData(t *testing.T) {
	cases := map[string]string{
		"HTML error":     "<html>unavailable</html>",
		"empty":          "",
		"no heading":     exampleStamp,
		"bad base64":     "## test\nsdns://!!",
		"truncated":      "## test\nsdns://Ag",
		"bad IP":         "## test\n" + fixtureStamp("not-an-ip", "resolver.example", "/dns-query", false),
		"empty host":     "## test\n" + fixtureStamp("", "", "/dns-query", false),
		"relative path":  "## test\n" + fixtureStamp("", "resolver.example", "dns-query", false),
		"fragment":       "## test\n" + fixtureStamp("", "resolver.example", "/dns-query#fragment", false),
		"invalid port":   "## test\n" + fixtureStamp("", "resolver.example:99999", "/dns-query", false),
		"host injection": "## test\n" + fixtureStamp("", "resolver.example/other", "/dns-query", false),
		"partial list":   "## good\n" + exampleStamp + "\n## bad\nsdns://Ag",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := parse([]byte(body)); err == nil {
				t.Fatal("invalid source accepted")
			}
		})
	}
}
