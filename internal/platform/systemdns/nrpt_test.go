package systemdns

import (
	"errors"
	"strings"
	"testing"

	"doh-finder/internal/pkg/ds"
)

func TestNRPTChecksOnlyEffectiveRoutingForVerificationNames(t *testing.T) {
	route := func(ns string) ds.NRPTPolicy {
		return ds.NRPTPolicy{Namespace: ns, NameServers: []string{"192.0.2.53"}}
	}
	for _, tc := range []struct {
		name     string
		policies []ds.NRPTPolicy
		blocked  bool
	}{
		{"no policy", nil, false},
		{"unrelated corporate suffix", []ds.NRPTPolicy{route(".corp.example")}, false},
		{"suffix boundary", []ds.NRPTPolicy{route(".ample.com")}, false},
		{"exact sibling", []ds.NRPTPolicy{route("iana.org")}, false},
		{"reverse lookup", []ds.NRPTPolicy{route(".in-addr.arpa")}, false},
		{"global override", []ds.NRPTPolicy{route(".")}, true},
		{"exact match case and trailing dot", []ds.NRPTPolicy{route("EXAMPLE.COM.")}, true},
		{"suffix covers apex", []ds.NRPTPolicy{route(".example.com")}, true},
		{"suffix covers child", []ds.NRPTPolicy{route(".iana.org")}, true},
		{"host prefix", []ds.NRPTPolicy{route("www")}, true},
		{"unrelated host prefix", []ds.NRPTPolicy{route("mail")}, false},
		{"DNSSEC only", []ds.NRPTPolicy{{Namespace: ".", DNSSECValidationRequired: true}}, false},
		{"DirectAccess exemption", []ds.NRPTPolicy{{Namespace: ".", DirectAccessEnabled: true}}, false},
		{"inactive DirectAccess DNS", []ds.NRPTPolicy{{Namespace: ".", DirectAccessDNSServers: []string{"192.0.2.54"}}}, false},
		{"active DirectAccess DNS", []ds.NRPTPolicy{{Namespace: ".", DirectAccessEnabled: true, DirectAccessDNSServers: []string{"192.0.2.54"}}}, true},
		{"explicit test exemptions", []ds.NRPTPolicy{route("."), {Namespace: "example.com"}, {Namespace: "www.iana.org"}}, false},
		{"more specific suffix exemptions", []ds.NRPTPolicy{route("."), {Namespace: ".example.com"}, {Namespace: ".iana.org"}}, false},
		{"partial exemption", []ds.NRPTPolicy{route("."), {Namespace: "example.com"}}, true},
		{"ambiguous prefix and suffix", []ds.NRPTPolicy{route("www"), {Namespace: ".iana.org"}}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := checkNRPT(tc.policies, verificationDomains)
			if errors.Is(err, ds.ErrDNSPolicyConflict) != tc.blocked {
				t.Fatalf("blocked=%t, error=%v", tc.blocked, err)
			}
			if tc.blocked && (!strings.Contains(err.Error(), "192.0.2.") || !strings.Contains(err.Error(), "namespace") || !strings.Contains(err.Error(), "--status")) {
				t.Fatalf("missing actionable diagnostics: %v", err)
			}
		})
	}
}
