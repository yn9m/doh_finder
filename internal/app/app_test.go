package app

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestInvalidFlagsStopBeforeAnyNetworkOrDNSChange(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"--update", "--full-cycle"}, "choose one mode"},
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
	for _, flag := range []string{"-update", "-check", "-browse", "-full-cycle", "-priorities", "-continue", "-start-over"} {
		if !strings.Contains(stderr.String(), flag) {
			t.Errorf("help omits %s", flag)
		}
	}
}
