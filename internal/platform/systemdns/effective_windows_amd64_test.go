package systemdns

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"doh-finder/internal/pkg/ds"
)

func TestEffectiveDNSWaitsForWindowsUpdate(t *testing.T) {
	snapshot := ds.DNSSnapshot{InterfaceIndex: 7, InterfaceGUID: "wifi-guid", InterfaceName: "Wi-Fi"}
	s := NewSystem(time.Second)
	calls := 0
	s.active = func(context.Context) (ds.DNSSnapshot, error) {
		calls++
		current := snapshot
		current.Servers = []string{"192.0.2.1"}
		if calls == 1 {
			current.Servers = []string{"192.0.2.254"} // Previous DHCP DNS.
		}
		return current, nil
	}
	if err := s.verifyEffective(context.Background(), snapshot, "192.0.2.1"); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("did not wait for effective settings: %d calls", calls)
	}
}

func TestEffectiveDNSRejectsOverridesAndExtraBackup(t *testing.T) {
	for _, servers := range [][]string{{"192.0.2.254"}, {"192.0.2.1", "192.0.2.2"}, {}} {
		t.Run(strings.Join(servers, ","), func(t *testing.T) {
			t.Parallel()
			snapshot := ds.DNSSnapshot{InterfaceIndex: 7, InterfaceGUID: "wifi-guid", InterfaceName: "Wi-Fi", Servers: servers}
			s := NewSystem(time.Second)
			s.active = func(context.Context) (ds.DNSSnapshot, error) { return snapshot, nil }
			err := s.verifyEffective(context.Background(), snapshot, "192.0.2.1")
			if !errors.Is(err, ds.ErrDNSSettingsOverridden) || !strings.Contains(err.Error(), "Windows uses ["+strings.Join(servers, ",")+"]") {
				t.Fatalf("effective mismatch accepted or hidden: %v", err)
			}
		})
	}
}

func TestEffectiveDNSDoesNotAcceptAnotherAdapterOrReorderedPair(t *testing.T) {
	snapshot := ds.DNSSnapshot{InterfaceIndex: 7, InterfaceGUID: "wifi-guid", InterfaceName: "Wi-Fi"}
	s := NewSystem(time.Second)
	s.active = func(context.Context) (ds.DNSSnapshot, error) {
		return ds.DNSSnapshot{InterfaceIndex: 14, InterfaceGUID: "ethernet-guid", Servers: []string{"192.0.2.1"}}, nil
	}
	if err := s.verifyEffective(context.Background(), snapshot, "192.0.2.1"); !errors.Is(err, ds.ErrActiveInterfaceChanged) {
		t.Fatalf("DNS on another adapter accepted: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	snapshot.Servers = []string{"192.0.2.2", "192.0.2.1"}
	s.active = func(context.Context) (ds.DNSSnapshot, error) { return snapshot, nil }
	if err := s.verifyEffective(ctx, snapshot, "192.0.2.1,192.0.2.2"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("reversed primary/backup accepted or cancellation lost: %v", err)
	}
}
