package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"doh-finder/internal/pkg/ds"
)

type serviceFunc func(context.Context) (ds.Catalog, error)

func (f serviceFunc) Update(ctx context.Context) (ds.Catalog, error) { return f(ctx) }

func TestMenuSelectionAndRetry(t *testing.T) {
	calls := 0
	service := serviceFunc(func(ctx context.Context) (ds.Catalog, error) {
		calls++
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("update has no deadline")
		}
		if calls == 1 {
			return ds.Catalog{}, errors.New("network unavailable")
		}
		return ds.Catalog{Resolvers: []ds.Resolver{{Name: "test"}}}, nil
	})
	var output bytes.Buffer
	handler := NewHandler(service, nil, slog.New(slog.NewTextHandler(io.Discard, nil)), &output)
	if err := handler.Menu(context.Background(), strings.NewReader("bad\n\n1\n\n 1 \r\n\n0\n"), time.Second, "servers.json", "report.json"); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("got %d updates, want 2", calls)
	}
	for _, want := range []string{"1. Update Server List", "0. Exit", "Invalid option", "Update failed: network unavailable", "Server list updated: 1 IPv4", "Goodbye!"} {
		if !strings.Contains(output.String(), want) {
			t.Errorf("missing %q in %s", want, output.String())
		}
	}
}

func TestMenuDoesNotUpdateOnExitOrEOF(t *testing.T) {
	for _, input := range []string{"0\n", ""} {
		var output bytes.Buffer
		service := serviceFunc(func(context.Context) (ds.Catalog, error) {
			t.Fatal("updated without option 1")
			return ds.Catalog{}, nil
		})
		handler := NewHandler(service, nil, slog.Default(), &output)
		if err := handler.Menu(context.Background(), strings.NewReader(input), time.Second, "servers.json", "report.json"); err != nil {
			t.Fatal(err)
		}
	}
}

func TestMenuGivesRetryFreshDeadline(t *testing.T) {
	calls := 0
	service := serviceFunc(func(ctx context.Context) (ds.Catalog, error) {
		calls++
		if calls == 1 {
			<-ctx.Done()
			return ds.Catalog{}, ctx.Err()
		}
		if ctx.Err() != nil {
			t.Fatal("retry inherited expired context")
		}
		return ds.Catalog{}, nil
	})
	var output bytes.Buffer
	handler := NewHandler(service, nil, slog.Default(), &output)
	if err := handler.Menu(context.Background(), strings.NewReader("1\n\n1\n\n0\n"), 20*time.Millisecond, "servers.json", "report.json"); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("got %d updates", calls)
	}
}

func TestMenuCancellationWhileWaitingForInput(t *testing.T) {
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	ctx, cancel := context.WithCancel(context.Background())
	var output bytes.Buffer
	handler := NewHandler(serviceFunc(func(context.Context) (ds.Catalog, error) {
		t.Error("unexpected update")
		return ds.Catalog{}, nil
	}), nil, slog.Default(), &output)
	done := make(chan error, 1)
	go func() { done <- handler.Menu(ctx, reader, time.Second, "servers.json", "report.json") }()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("menu did not stop after cancellation")
	}
}
