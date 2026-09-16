package dnscrypt

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestFetchPinsRevisionAndTracksSource(t *testing.T) {
	revision := strings.Repeat("a", 40)
	body := "## resolver\n" + exampleStamp + "\n"
	requests := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.URL.Path)
		switch r.URL.Path {
		case "/revision":
			fmt.Fprintf(w, `{"sha":%q}`, revision)
		case "/" + revision + "/v3/public-resolvers.md":
			fmt.Fprint(w, body)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client := NewClient(server.Client(), "master")
	client.apiURL = server.URL + "/revision"
	client.rawBaseURL = server.URL + "/"
	got, err := client.Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(requests) != 2 || got.Source.Revision != revision || len(got.Resolvers) != 1 {
		t.Fatalf("unexpected fetch: %+v; requests %v", got, requests)
	}
	if got.Source.SHA256 != fmt.Sprintf("%x", sha256.Sum256([]byte(body))) {
		t.Fatal("hash does not match downloaded bytes")
	}
	if _, err := time.Parse(time.RFC3339, got.Source.RetrievedAt); err != nil {
		t.Fatal(err)
	}
}

func TestFetchFailsForHTTPErrorAndCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()
	client := NewClient(server.Client(), strings.Repeat("a", 40))
	client.rawBaseURL = server.URL + "/"
	if _, err := client.Fetch(context.Background()); err == nil || !strings.Contains(err.Error(), "503") {
		t.Fatalf("expected HTTP error, got %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := client.Fetch(ctx); err == nil {
		t.Fatal("ignored cancellation")
	}
}

func TestFetchRejectsBadRevision(t *testing.T) {
	client := NewClient(&http.Client{}, "../bad")
	if _, err := client.Fetch(context.Background()); err == nil {
		t.Fatal("bad revision accepted")
	}
}
