package systemdns

import (
	"fmt"
	"strings"

	"doh-finder/internal/pkg/ds"
)

var verificationDomains = []string{"example.com", "www.iana.org"}

// Unrelated NRPT rules, DNSSEC requirements and explicit exemptions can coexist
// with adapter DNS. A rule which selects another resolver for our test names
// would make a successful Windows query meaningless for the candidate.
func checkNRPT(policies []ds.NRPTPolicy, domains []string) error {
	for _, domain := range domains {
		for _, p := range applicableNRPT(policies, domain) {
			target := ""
			if len(p.NameServers) > 0 {
				target = "DNS " + strings.Join(p.NameServers, ", ")
			}
			if p.DirectAccessEnabled && len(p.DirectAccessDNSServers) > 0 {
				target = "DirectAccess DNS " + strings.Join(p.DirectAccessDNSServers, ", ")
			}
			if target != "" {
				return fmt.Errorf("%w: %s matches namespace %q, which selects %s. Auto Browse cannot verify the chosen adapter DNS while this rule is active. Check option 5 / --status; pause or reconfigure the VPN/DNS software or policy that owns this rule, then retry", ds.ErrDNSPolicyConflict, domain, p.Namespace, target)
			}
		}
	}
	return nil
}

func applicableNRPT(policies []ds.NRPTPolicy, domain string) []ds.NRPTPolicy {
	domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	var exact, suffix, prefix, defaults []ds.NRPTPolicy
	longestSuffix := -1
	for _, p := range policies {
		ns := strings.ToLower(strings.TrimSpace(p.Namespace))
		if ns == "." {
			defaults = append(defaults, p)
			continue
		}
		ns = strings.TrimSuffix(ns, ".")
		if strings.HasPrefix(ns, ".") {
			name := strings.TrimPrefix(ns, ".")
			if name == "" || domain != name && !strings.HasSuffix(domain, "."+name) {
				continue
			}
			if len(name) > longestSuffix {
				suffix, longestSuffix = nil, len(name)
			}
			if len(name) == longestSuffix {
				suffix = append(suffix, p)
			}
		} else if ns == domain {
			exact = append(exact, p)
		} else if !strings.Contains(ns, ".") && ns != "" && strings.SplitN(domain, ".", 2)[0] == ns {
			prefix = append(prefix, p)
		}
	}
	// More specific FQDN and child suffix rules supersede broad rules. This is
	// essential for NRPT exemptions, which have no alternative DNS servers.
	if len(exact) > 0 {
		return exact
	}
	if len(suffix)+len(prefix) > 0 {
		// Conservatively check both when host-prefix and suffix rules overlap;
		// do not let an ambiguous overlap falsely certify candidate isolation.
		return append(suffix, prefix...)
	}
	return defaults
}
