package catalog

import (
	"fmt"
	"net/netip"
	"net/url"

	"doh-finder/internal/pkg/ds"
)

// Only endpoints with an explicit IPv4 address in the source are retained.
// Import does not resolve names or probe connectivity.
func ipv4Resolvers(resolvers []ds.Resolver) ([]ds.Resolver, error) {
	filtered := make([]ds.Resolver, 0, len(resolvers))
	for _, resolver := range resolvers {
		if resolver.IP == nil {
			continue
		}
		address, err := netip.ParseAddr(*resolver.IP)
		if err != nil {
			return nil, fmt.Errorf("%s: invalid endpoint IP: %w", resolver.Name, err)
		}
		if !address.Is4() {
			continue
		}
		endpoint, err := url.Parse(resolver.DoHURL)
		if err != nil {
			return nil, fmt.Errorf("%s: invalid DoH URL: %w", resolver.Name, err)
		}
		if address, err := netip.ParseAddr(endpoint.Hostname()); err == nil && !address.Is4() {
			continue
		}
		bootstrap := make([]string, 0, len(resolver.BootstrapDNS))
		for _, value := range resolver.BootstrapDNS {
			address, err := netip.ParseAddr(value)
			if err != nil {
				return nil, fmt.Errorf("%s: invalid bootstrap DNS IP: %w", resolver.Name, err)
			}
			if address.Is4() {
				bootstrap = append(bootstrap, value)
			}
		}
		resolver.BootstrapDNS = bootstrap
		filtered = append(filtered, resolver)
	}
	return filtered, nil
}
