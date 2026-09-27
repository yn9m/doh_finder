package cli

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"doh-finder/internal/pkg/ds"
)

func TestStatusShowsEffectiveAndSavedDNSSeparately(t *testing.T) {
	var out bytes.Buffer
	h := NewHandler(nil, nil, slog.Default(), &out).WithStatus(func(context.Context) (ds.DNSStatus, error) {
		return ds.DNSStatus{WindowsVersion: "11 test", Adapter: ds.DNSSnapshot{
			InterfaceName: "Wi-Fi", InterfaceIndex: 7, InterfaceGUID: "wifi-guid",
			NameServer: "192.0.2.1", Servers: []string{"192.0.2.254"},
			DoH: []ds.DoHSetting{{Index: 0, Template: "https://dns.example/dns-query", Flags: 2}},
		}}, nil
	})
	if err := h.Menu(context.Background(), strings.NewReader("5\n\n0\n"), time.Second, "unused", "unused"); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"CURRENT DNS SETTINGS", "Active adapter: Wi-Fi (index 7)", "Effective IPv4 DNS: 192.0.2.254", "Saved adapter IPv4 DNS: 192.0.2.1", "https://dns.example/dns-query", "Hardware properties", "Read-only status"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q in %s", want, out.String())
		}
	}
}

func TestStatusRetainsEffectiveDNSWhenDoHReadFails(t *testing.T) {
	var out bytes.Buffer
	h := NewHandler(nil, nil, slog.Default(), &out).WithStatus(func(context.Context) (ds.DNSStatus, error) {
		return ds.DNSStatus{Adapter: ds.DNSSnapshot{Servers: []string{"192.0.2.1"}}, SettingsError: "profile-specific DNS", DoHError: "policy disabled"}, nil
	})
	if err := h.Status(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"192.0.2.1", "profile-specific DNS", "policy disabled"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("missing %q in %s", want, out.String())
		}
	}
}
