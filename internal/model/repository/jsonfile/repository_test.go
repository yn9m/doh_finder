package jsonfile

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"doh-finder/internal/pkg/ds"
)

func TestSaveReplacesExistingFileAndCleansTemporaryFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "configs", "servers.json")
	repo := NewRepository(path)
	for _, name := range []string{"first", "second"} {
		value := ds.Catalog{SchemaVersion: 1, Resolvers: []ds.Resolver{{Name: name}}}
		if err := repo.Save(context.Background(), value); err != nil {
			t.Fatal(err)
		}
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var got ds.Catalog
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Resolvers) != 1 || got.Resolvers[0].Name != "second" {
		t.Fatalf("incorrect replacement: %+v", got)
	}
	files, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 {
		t.Fatalf("temporary files left behind: %v", files)
	}
	before := string(body)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := repo.Save(ctx, ds.Catalog{}); err == nil {
		t.Fatal("ignored cancellation")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != before {
		t.Fatal("cancelled save changed file")
	}
}

func TestFailedReplacementCleansTemporaryFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "occupied")
	if err := os.Mkdir(path, 0755); err != nil {
		t.Fatal(err)
	}
	if err := NewRepository(path).Save(context.Background(), ds.Catalog{}); err == nil {
		t.Fatal("expected replacement error")
	}
	files, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 || files[0].Name() != "occupied" {
		t.Fatalf("temporary file left behind: %v", files)
	}
}

func TestStateRoundTripMissingAndCorrupt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	repo := NewRepository(path)
	ctx := context.Background()
	if _, exists, err := repo.LoadState(ctx); err != nil || exists {
		t.Fatal("missing state should mean first run")
	}
	state := ds.BrowseState{SchemaVersion: 1, Current: 2, Priorities: []int{1, 2, 3}, Pending: &ds.DNSSnapshot{InterfaceIndex: 14, Automatic: true, NameServer: "", DoH: []ds.DoHSetting{{Index: 0, Flags: 17, Template: "https://dns.example/dns-query"}}}}
	if err := repo.SaveState(ctx, state); err != nil {
		t.Fatal(err)
	}
	loaded, exists, err := NewRepository(path).LoadState(ctx)
	if err != nil || !exists || loaded.Current != 2 || loaded.Pending == nil || !loaded.Pending.Automatic || loaded.Pending.DoH[0].Flags != 17 {
		t.Fatalf("lost durable recovery state: %+v %v", loaded, err)
	}
	if err := os.WriteFile(path, []byte("broken"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, exists, err := repo.LoadState(ctx); err == nil || !exists {
		t.Fatal("corruption must not be treated as first run")
	}
}
