package catalog

import (
	"context"
	"testing"

	"doh-finder/internal/pkg/ds"
)

func TestUpdateExcludesMissingIPsAndIPv6(t *testing.T) {
	ipv4, ipv6, mapped := "192.0.2.1", "2001:db8::1", "::ffff:192.0.2.1"
	repo := &repositoryStub{}
	source := sourceStub{value: ds.Catalog{Resolvers: []ds.Resolver{
		{Name: "dual", IP: &ipv4, DoHURL: "https://dual.example/dns-query",
			Stamp: "original-stamp", BootstrapDNS: []string{"2001:db8::53", "192.0.2.53"}},
		{Name: "dual", IP: &ipv6, DoHURL: "https://dual.example/dns-query"},
		{Name: "ipv6-only", IP: &ipv6, DoHURL: "https://ipv6.example/dns-query"},
		{Name: "literal-ipv6", IP: &ipv4, DoHURL: "https://[2001:db8::1]:8443/dns-query"},
		{Name: "mapped-ipv6", IP: &mapped, DoHURL: "https://mapped.example/dns-query"},
		{Name: "hostname", DoHURL: "https://hostname.example/dns-query",
			BootstrapDNS: []string{"2001:db8::53"}},
	}}}
	got, err := NewService(source, repo).Update(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if repo.calls != 1 || len(repo.value.Resolvers) != 1 || len(got.Resolvers) != 1 {
		t.Fatalf("expected only the explicit IPv4 endpoint: %+v", got)
	}
	dual := got.Resolvers[0]
	if dual.Name != "dual" || dual.IP == nil || *dual.IP != ipv4 || dual.Stamp != "original-stamp" {
		t.Fatalf("lost IPv4 endpoint or original stamp: %+v", dual)
	}
	if len(dual.BootstrapDNS) != 1 || dual.BootstrapDNS[0] != "192.0.2.53" {
		t.Fatalf("incorrect bootstrap filter: %v", dual.BootstrapDNS)
	}
}

func TestUpdatePreservesCatalogWhenAllIPsAreMissing(t *testing.T) {
	repo := &repositoryStub{}
	source := sourceStub{value: ds.Catalog{Resolvers: []ds.Resolver{
		{Name: "hostname", DoHURL: "https://hostname.example/dns-query"},
	}}}
	if _, err := NewService(source, repo).Update(context.Background()); err == nil {
		t.Fatal("expected no eligible endpoints error")
	}
	if repo.calls != 0 {
		t.Fatal("overwrote existing catalog with an empty filtered list")
	}
}

func TestUpdatePreservesCatalogWhenSourceIsIPv6Only(t *testing.T) {
	ipv6 := "2001:db8::1"
	repo := &repositoryStub{}
	source := sourceStub{value: ds.Catalog{Resolvers: []ds.Resolver{
		{Name: "ipv6-only", IP: &ipv6, DoHURL: "https://v6.example/dns-query"},
	}}}
	if _, err := NewService(source, repo).Update(context.Background()); err == nil {
		t.Fatal("expected no eligible endpoints error")
	}
	if repo.calls != 0 {
		t.Fatal("overwrote existing catalog with an empty filtered list")
	}
}
