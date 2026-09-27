package app

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInvalidFlagsStopBeforeAnyNetworkOrDNSChange(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"--update", "--full-cycle"}, "choose one mode"},
		{[]string{"--status", "--browse"}, "choose one mode"},
		{[]string{"--status", "--continue"}, "require --browse or --full-cycle"},
		{[]string{"--browse", "--continue", "--start-over"}, "cannot be combined"},
		{[]string{"--continue"}, "require --browse or --full-cycle"},
		{[]string{"--full-cycle", "--priorities", "1,2,3"}, "priorities must list"},
		{[]string{"--full-cycle", "--priorities", "no-filter,no-filter,dnssec"}, "priorities must list"},
	} {
		var out, errOut bytes.Buffer
		code := Run(context.Background(), tc.args, strings.NewReader(""), &out, &errOut)
		if code != 2 || !strings.Contains(errOut.String(), tc.want) || out.Len() != 0 {
			t.Fatalf("args %v: code %d, stdout %q, stderr %q", tc.args, code, out.String(), errOut.String())
		}
	}
}

func TestHelpListsEachHeadlessMode(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := Run(context.Background(), []string{"--help"}, strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("help exit=%d: %s", code, stderr.String())
	}
	for _, flag := range []string{"-update", "-check", "-browse", "-full-cycle", "-status", "-priorities", "-continue", "-start-over"} {
		if !strings.Contains(stderr.String(), flag) {
			t.Errorf("help omits %s", flag)
		}
	}
}

func TestDefaultDataDirFromFreshCheckout(t *testing.T) {
	t.Chdir(t.TempDir())
	if err := os.MkdirAll(filepath.Join("cmd", "doh-finder"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("go.mod", []byte("module doh-finder\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join("cmd", "doh-finder", "main.go"), []byte("package main\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if got := defaultDataDir(); got != "." {
		t.Fatalf("fresh checkout data directory = %q, want project root", got)
	}
}

func TestStatusBypassesSavedStateAndRecovery(t *testing.T) {
	// An invalid journal must not prevent read-only diagnostics. Cancel the
	// platform query so this test never depends on the host's network state.
	statePath := filepath.Join(t.TempDir(), "browse.json")
	contents := []byte(`{"pendingRestore": invalid journal`)
	if err := os.WriteFile(statePath, contents, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var stdout, stderr bytes.Buffer
	code := Run(ctx, []string{"--status", "--state", statePath}, strings.NewReader(""), &stdout, &stderr)
	if code != 1 || !strings.Contains(stderr.String(), "read current DNS") || strings.Contains(stderr.String(), "load saved DNS state") {
		t.Fatalf("status tried to load/recover state: code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	after, err := os.ReadFile(statePath)
	if err != nil || !bytes.Equal(after, contents) {
		t.Fatal("status changed the journal")
	}
}
