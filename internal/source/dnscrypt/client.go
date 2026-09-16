package dnscrypt

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"time"

	"doh-finder/internal/pkg/ds"
)

const repository = "https://github.com/DNSCrypt/dnscrypt-resolvers"
const maxDownload = 8 << 20

var revisionPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)

type Client struct {
	http       *http.Client
	revision   string
	apiURL     string
	rawBaseURL string
}

func NewClient(client *http.Client, revision string) *Client {
	return &Client{
		http:       client,
		revision:   revision,
		apiURL:     "https://api.github.com/repos/DNSCrypt/dnscrypt-resolvers/commits/master",
		rawBaseURL: "https://raw.githubusercontent.com/DNSCrypt/dnscrypt-resolvers/",
	}
}

func (c *Client) Fetch(ctx context.Context) (ds.Catalog, error) {
	revision := c.revision
	if revision == "master" {
		body, err := c.get(ctx, c.apiURL)
		if err != nil {
			return ds.Catalog{}, fmt.Errorf("resolve source revision: %w", err)
		}
		var commit struct {
			SHA string `json:"sha"`
		}
		if err := json.Unmarshal(body, &commit); err != nil {
			return ds.Catalog{}, fmt.Errorf("decode source revision: %w", err)
		}
		revision = commit.SHA
	}
	if !revisionPattern.MatchString(revision) {
		return ds.Catalog{}, fmt.Errorf("invalid source revision %q: expected master or a 40-character commit SHA", revision)
	}
	sourceURL := c.rawBaseURL + revision + "/v3/public-resolvers.md"
	body, err := c.get(ctx, sourceURL)
	if err != nil {
		return ds.Catalog{}, fmt.Errorf("download public resolvers: %w", err)
	}
	resolvers, err := parse(body)
	if err != nil {
		return ds.Catalog{}, fmt.Errorf("parse public resolvers: %w", err)
	}
	digest := sha256.Sum256(body)
	return ds.Catalog{
		Source: ds.SourceInfo{
			Repository:  repository,
			Revision:    revision,
			URL:         sourceURL,
			SHA256:      hex.EncodeToString(digest[:]),
			RetrievedAt: time.Now().UTC().Format(time.RFC3339),
		},
		Resolvers: resolvers,
	}, nil
}

func (c *Client) get(ctx context.Context, url string) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	request.Header.Set("User-Agent", "doh-finder")
	response, err := c.http.Do(request)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", url, err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: HTTP %d", url, response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxDownload+1))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if len(body) > maxDownload {
		return nil, fmt.Errorf("response exceeds %d bytes", maxDownload)
	}
	return body, nil
}
