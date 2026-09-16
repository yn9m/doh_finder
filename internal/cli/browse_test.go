package cli

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"reflect"
	"strings"
	"testing"
	"time"

	"doh-finder/internal/pkg/ds"
)

type browseStub struct {
	state                               ds.BrowseState
	exists                              bool
	starts, tries, confirms, recoveries int
	priorities                          []int
	failTry                             bool
}

func (b *browseStub) Load(context.Context) (ds.BrowseState, bool, error) {
	return b.state, b.exists, nil
}
func (b *browseStub) Start(_ context.Context, p []int) (ds.BrowseState, error) {
	b.starts++
	b.priorities = p
	b.exists = true
	b.state.Priorities = p
	return b.state, nil
}
func (b *browseStub) StartAfterLast(ctx context.Context, p []int) (ds.BrowseState, error) {
	return b.Start(ctx, p)
}
func (b *browseStub) ResumeAfterLast(context.Context) (ds.BrowseState, error) {
	return b.state, nil
}
func (b *browseStub) TryNext(_ context.Context, progress func(string)) (ds.BrowseState, error) {
	b.tries++
	if progress != nil {
		progress("Applying candidate without backup")
	}
	if b.failTry {
		return b.state, errors.New("no servers passed; restored")
	}
	return b.state, nil
}
func (b *browseStub) Confirm(context.Context) (ds.BrowseState, error) {
	b.confirms++
	b.state.LastWorking = &b.state.Queue[0]
	return b.state, nil
}
func (b *browseStub) Recover(context.Context) error { b.recoveries++; return nil }

func TestPriorityInput(t *testing.T) {
	for _, input := range []string{"", "1 2 3", "3 2 1", "  2  1 3 "} {
		p, err := parsePriorities(input)
		if err != nil || len(p) != 3 {
			t.Fatalf("%q: %v", input, err)
		}
	}
	for _, input := range []string{"1 1 2", "123", "1 2", "1 2 3 4", "0 1 2", "a 2 3"} {
		if _, err := parsePriorities(input); err == nil {
			t.Fatalf("accepted %q", input)
		}
	}
}

func TestBrowseScreensFirstRunResumeAndExplicitConfirmation(t *testing.T) {
	for _, tc := range []struct {
		name, input             string
		existing                bool
		starts, tries, confirms int
	}{
		{"first run keep", "3\n\n2\n\n0\n", false, 1, 1, 1},
		{"resume next then keep", "3\n3 2 1\n2\n1\n2\n\n0\n", true, 0, 2, 1},
		{"restart", "3\n3 2 1\n1\n2\n\n0\n", true, 1, 1, 1},
		{"back without confirm", "3\n\n0\n0\n", false, 1, 1, 0},
		{"EOF without confirm", "3\n\n", false, 1, 1, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := &browseStub{exists: tc.existing, state: ds.BrowseState{SchemaVersion: 1, Priorities: []int{1, 2, 3}, Queue: []ds.ServerResult{{Name: "sample", IP: "192.0.2.1", DoHURL: "https://dns.example/dns-query"}}, Current: 0}}
			var screen bytes.Buffer
			frames := []string{}
			clear := func() error { frames = append(frames, screen.String()); screen.Reset(); return nil }
			h := NewHandler(nil, nil, slog.Default(), &screen).WithScreens(b, clear)
			if err := h.Menu(context.Background(), strings.NewReader(tc.input), time.Second, "servers.json", "report.json"); err != nil {
				t.Fatal(err)
			}
			frames = append(frames, screen.String())
			if b.starts != tc.starts || b.tries != tc.tries || b.confirms != tc.confirms || b.recoveries != 1 {
				t.Fatalf("wrong transitions: %+v", b)
			}
			all := strings.Join(frames, "\n")
			if strings.Contains(all, "2. Continue") != tc.existing {
				t.Fatal("wrong first-run/resume prompt")
			}
			for _, frame := range frames {
				if strings.Contains(frame, "DOH FINDER") && (strings.Contains(frame, "Priority order:") || strings.Contains(frame, "IPv4:")) {
					t.Fatal("submenu content leaked into main menu")
				}
				if strings.Contains(frame, "SERVER WORKS") && strings.Contains(frame, "SAVED SESSION") {
					t.Fatal("old prompt remained on server screen")
				}
			}
			if b.starts == 1 {
				want := []int{1, 2, 3}
				if tc.name == "restart" {
					want = []int{3, 2, 1}
				}
				if !reflect.DeepEqual(b.priorities, want) {
					t.Fatal("wrong priority order")
				}
			}
		})
	}
}

func TestUpdateScreenWaitsBeforeReturningToCleanMenu(t *testing.T) {
	var screen bytes.Buffer
	frames := []string{}
	h := NewHandler(serviceFunc(func(context.Context) (ds.Catalog, error) { return ds.Catalog{}, nil }), nil, slog.Default(), &screen).WithScreens(nil, func() error { frames = append(frames, screen.String()); screen.Reset(); return nil })
	if err := h.Menu(context.Background(), strings.NewReader("1\n\n0\n"), time.Second, "servers.json", "report.json"); err != nil {
		t.Fatal(err)
	}
	if len(frames) != 3 || !strings.Contains(frames[2], "Press Enter to return") || strings.Contains(frames[2], "2. Check Servers") || strings.Contains(screen.String(), "Server list updated") {
		t.Fatalf("screens were not separated: %q / %q", frames, screen.String())
	}
}
