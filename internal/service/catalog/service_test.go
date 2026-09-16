package catalog

import (
	"context"
	"errors"
	"testing"

	"doh-finder/internal/pkg/ds"
)

type sourceStub struct {
	value ds.Catalog
	err   error
}

func (s sourceStub) Fetch(context.Context) (ds.Catalog, error) { return s.value, s.err }

type repositoryStub struct {
	calls int
	value ds.Catalog
	err   error
}

func (r *repositoryStub) Save(_ context.Context, value ds.Catalog) error {
	r.calls++
	r.value = value
	return r.err
}

func TestUpdateSortsAndKeepsMultipleEndpoints(t *testing.T) {
	ip := "192.0.2.1"
	repo := &repositoryStub{}
	source := sourceStub{value: ds.Catalog{Resolvers: []ds.Resolver{
		{Name: "z", IP: &ip, Stamp: "2"}, {Name: "a", IP: &ip, Stamp: "2"}, {Name: "a", IP: &ip, Stamp: "1"},
	}}}
	got, err := NewService(source, repo).Update(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if repo.calls != 1 || got.SchemaVersion != 1 || len(got.Resolvers) != 3 ||
		got.Resolvers[0].Name != "a" || got.Resolvers[0].Stamp != "1" {
		t.Fatalf("unexpected catalog: %+v", got)
	}
}

func TestUpdatePreservesCatalogOnSourceFailure(t *testing.T) {
	for _, source := range []sourceStub{{err: errors.New("network failure")}, {}} {
		repo := &repositoryStub{}
		if _, err := NewService(source, repo).Update(context.Background()); err == nil {
			t.Fatal("expected failure")
		}
		if repo.calls != 0 {
			t.Fatal("overwrote catalog after source failure")
		}
	}
}

func TestUpdateReportsSaveFailure(t *testing.T) {
	ip := "192.0.2.1"
	want := errors.New("disk full")
	source := sourceStub{value: ds.Catalog{Resolvers: []ds.Resolver{{Name: "test", IP: &ip}}}}
	_, err := NewService(source, &repositoryStub{err: want}).Update(context.Background())
	if !errors.Is(err, want) {
		t.Fatalf("lost save error: %v", err)
	}
}
