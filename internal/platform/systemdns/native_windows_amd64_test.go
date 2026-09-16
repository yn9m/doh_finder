package systemdns

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
	"unsafe"

	"doh-finder/internal/model/repository/jsonfile"
	"doh-finder/internal/pkg/ds"
)

func TestNativeLayouts(t *testing.T) {
	if unsafe.Sizeof(interfaceSettings{}) != 112 || unsafe.Sizeof(serverProperty{}) != 24 || unsafe.Sizeof(dohSettings{}) != 16 || unsafe.Sizeof(queryRequest{}) != 64 || unsafe.Sizeof(queryResult{}) != 32 {
		t.Fatal("Windows x64 ABI layout mismatch")
	}
}

// Requires explicit opt-in and elevation. Applies the existing primary alone
// with mandatory DoH, checks it, and restores the entire original configuration.
func TestNativeApplyAndRestore(t *testing.T) {
	if os.Getenv("DOH_FINDER_LIVE_TEST") != "1" {
		t.Skip("opt-in elevated integration test")
	}
	release, err := LockSession()
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	system := NewSystem(15 * time.Second)
	ctx := context.Background()
	snapshot, err := system.Snapshot(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Servers) == 0 {
		t.Fatal("current adapter has no DNS server")
	}
	var template string
	for _, p := range snapshot.DoH {
		if p.Index == 0 {
			template = p.Template
		}
	}
	if template == "" {
		t.Fatal("current primary has no DoH template; test will not invent one")
	}
	candidate := ds.ServerResult{Name: "existing-primary-integration-test", IP: snapshot.Servers[0], DoHURL: template, Success: true, TCP: ds.ProbeResult{Status: "SUCCESS"}, DNS: []ds.DNSResult{{ProbeResult: ds.ProbeResult{Status: "SUCCESS"}, Domain: "example.com"}}}
	journal := os.Getenv("DOH_FINDER_LIVE_JOURNAL")
	if !filepath.IsAbs(journal) {
		t.Fatal("absolute recovery journal path required")
	}
	state := ds.BrowseState{SchemaVersion: 1, Priorities: []int{1, 2, 3}, Queue: []ds.ServerResult{candidate}, Pending: &snapshot}
	if err := jsonfile.NewRepository(journal).SaveState(ctx, state); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := system.Restore(context.Background(), snapshot); err != nil {
			t.Errorf("RESTORE FAILED; recovery journal %s: %v", journal, err)
			return
		}
		t.Log("Original IPv4 DNS and DoH settings restored and verified")
		if err := os.Remove(journal); err != nil {
			t.Error(err)
		}
	})
	if err := system.Apply(ctx, snapshot, candidate, nil); err != nil {
		t.Fatal(err)
	}
	t.Log("Only the existing primary is configured; mandatory DoH without fallback")
	for _, domain := range []string{"example.com", "www.iana.org"} {
		addresses, err := Resolve(snapshot.InterfaceIndex, domain)
		if err != nil {
			t.Fatal(err)
		}
		if err := checkSite(ctx, domain, addresses, 15*time.Second); err != nil {
			t.Fatal(err)
		}
		t.Logf("Windows DNS + HTTPS passed: %s", domain)
	}
}

// Opt-in read-only smoke test: no DNS settings are changed.
func TestNativeReadOnly(t *testing.T) {
	if os.Getenv("DOH_FINDER_READ_TEST") != "1" {
		t.Skip("opt-in native read-only test")
	}
	snapshot, err := inspect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := checkDoHAllowed(); err != nil {
		t.Fatal(err)
	}
	names, props, err := nativeRead(snapshot.InterfaceGUID)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("adapter=%s index=%d names=%s properties=%+v", snapshot.InterfaceName, snapshot.InterfaceIndex, names, props)
	addresses, err := Resolve(snapshot.InterfaceIndex, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Windows DNS A response: %v", addresses)
}
