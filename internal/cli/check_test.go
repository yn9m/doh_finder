package cli

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"doh-finder/internal/pkg/ds"
)

type checkFunc func(context.Context, func(ds.CheckProgress)) (ds.CheckReport, error)

func (f checkFunc) Run(ctx context.Context, progress func(ds.CheckProgress)) (ds.CheckReport, error) {
	return f(ctx, progress)
}

func TestOptionTwoChecksAndReturnsToMenuAfterFailure(t *testing.T) {
	var output bytes.Buffer
	calls := 0
	checker := checkFunc(func(ctx context.Context, progress func(ds.CheckProgress)) (ds.CheckReport, error) {
		calls++
		if calls == 1 {
			return ds.CheckReport{}, errors.New("list missing")
		}
		failed := ds.ServerResult{Name: "failed", TCP: ds.ProbeResult{Status: "TIMEOUT", Error: "timed out"}}
		progress(ds.CheckProgress{Completed: 1, Total: 2, Result: failed})
		result := ds.ServerResult{Name: "test", IP: "192.0.2.1", Properties: ds.Properties{NoFilter: true, DNSSEC: true}, TCP: ds.ProbeResult{Status: "SUCCESS", ElapsedMS: 12}, Success: true}
		progress(ds.CheckProgress{Completed: 2, Total: 2, Result: result})
		return ds.CheckReport{Checked: 2, Failed: 1, Results: []ds.ServerResult{result}}, nil
	})
	handler := NewHandler(serviceFunc(func(context.Context) (ds.Catalog, error) {
		t.Fatal("option 2 must not update from GitHub")
		return ds.Catalog{}, nil
	}), checker, slog.Default(), &output)
	if err := handler.Menu(context.Background(), strings.NewReader("2\n\n2\n\n0\n"), time.Second, "servers.json", "report.json"); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("checks=%d", calls)
	}
	for _, text := range []string{"2. Check Servers", "Check failed: list missing", "Check complete: 1/2", "1 with failures", "Only successful servers are saved", "NoFilter: true | NoLog: false | DNSSEC: true", "TCP: SUCCESS (12 ms)", "TCP: timed out", "Report saved to: report.json", "Goodbye!"} {
		if !strings.Contains(output.String(), text) {
			t.Errorf("missing %q", text)
		}
	}
}
