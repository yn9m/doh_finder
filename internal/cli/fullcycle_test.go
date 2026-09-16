package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"reflect"
	"strings"
	"testing"
	"time"

	"doh-finder/internal/pkg/ds"
)

type cycleBrowser struct {
	events *[]string
	state  ds.BrowseState
}

func (b *cycleBrowser) Load(context.Context) (ds.BrowseState, bool, error) {
	return b.state, false, nil
}
func (b *cycleBrowser) Start(context.Context, []int) (ds.BrowseState, error) {
	*b.events = append(*b.events, "start")
	return b.state, nil
}
func (b *cycleBrowser) StartAfterLast(context.Context, []int) (ds.BrowseState, error) {
	*b.events = append(*b.events, "start-after-last")
	return b.state, nil
}
func (b *cycleBrowser) ResumeAfterLast(context.Context) (ds.BrowseState, error) {
	*b.events = append(*b.events, "resume")
	return b.state, nil
}
func (b *cycleBrowser) TryNext(_ context.Context, progress func(string)) (ds.BrowseState, error) {
	*b.events = append(*b.events, "try")
	progress("Testing candidate")
	return b.state, nil
}
func (b *cycleBrowser) Confirm(context.Context) (ds.BrowseState, error) {
	*b.events = append(*b.events, "confirm")
	b.state.LastWorking = &b.state.Queue[0]
	return b.state, nil
}
func (b *cycleBrowser) Recover(context.Context) error {
	*b.events = append(*b.events, "recover")
	return nil
}

func cycleHandler(t *testing.T, events *[]string, updateErr, checkErr error, output io.Writer) *Handler {
	t.Helper()
	updater := serviceFunc(func(ctx context.Context) (ds.Catalog, error) {
		*events = append(*events, "update")
		if _, ok := ctx.Deadline(); !ok {
			t.Error("update has no deadline")
		}
		return ds.Catalog{Resolvers: []ds.Resolver{{Name: "test"}}}, updateErr
	})
	checker := checkFunc(func(context.Context, func(ds.CheckProgress)) (ds.CheckReport, error) {
		*events = append(*events, "check")
		return ds.CheckReport{Checked: 1, Results: []ds.ServerResult{{Name: "test", Success: true}}}, checkErr
	})
	browser := &cycleBrowser{events: events, state: ds.BrowseState{Queue: []ds.ServerResult{{Name: "test", IP: "192.0.2.1", DoHURL: "https://dns.example/dns-query"}}, Current: 0}}
	return NewHandler(updater, checker, slog.New(slog.NewTextHandler(io.Discard, nil)), output).WithScreens(browser, nil)
}

func TestHeadlessFullCycleOrderAndFailures(t *testing.T) {
	for _, tc := range []struct {
		name                string
		updateErr, checkErr error
		continueAfter       bool
		want                []string
	}{
		{"start over", nil, nil, false, []string{"update", "check", "start", "try", "confirm", "recover"}},
		{"continue from fresh report", nil, nil, true, []string{"update", "check", "start-after-last", "try", "confirm", "recover"}},
		{"update failed", errors.New("download failed"), nil, false, []string{"update"}},
		{"check failed", nil, errors.New("no report"), false, []string{"update", "check"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			events := []string{}
			var output bytes.Buffer
			h := cycleHandler(t, &events, tc.updateErr, tc.checkErr, &output)
			err := h.FullCycle(context.Background(), time.Second, []int{1, 2, 3}, tc.continueAfter)
			if (err != nil) != (tc.updateErr != nil || tc.checkErr != nil) {
				t.Fatalf("error=%v", err)
			}
			if !reflect.DeepEqual(events, tc.want) {
				t.Fatalf("events=%v, want=%v", events, tc.want)
			}
			if err == nil && (!strings.Contains(output.String(), "Testing candidate") || !strings.Contains(output.String(), "Active DNS:")) {
				t.Fatal("missing headless progress or result")
			}
		})
	}
}

func TestMenuFullCycleShowsSeparateStages(t *testing.T) {
	events := []string{}
	var screen bytes.Buffer
	frames := []string{}
	h := cycleHandler(t, &events, nil, nil, &screen)
	h.clear = func() error { frames = append(frames, screen.String()); screen.Reset(); return nil }
	if err := h.Menu(context.Background(), strings.NewReader("4\n\n2\n\n0\n"), time.Second, "servers.json", "report.json"); err != nil {
		t.Fatal(err)
	}
	frames = append(frames, screen.String())
	if !reflect.DeepEqual(events, []string{"update", "check", "start", "try", "confirm", "recover"}) {
		t.Fatal(events)
	}
	joined := strings.Join(frames, "\n")
	for _, want := range []string{"4. Full Cycle", "FULL CYCLE - UPDATE SERVER LIST", "FULL CYCLE - CHECK SERVERS", "AUTO BROWSE - PRIORITIES", "AUTO BROWSE - SERVER WORKS", "AUTO BROWSE - SAVED"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %s", want)
		}
	}
	for _, frame := range frames {
		if strings.Contains(frame, "FULL CYCLE - CHECK SERVERS") && strings.Contains(frame, "Updating server list") {
			t.Fatal("previous stage visible on check screen")
		}
	}
}
