package jsonfile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"doh-finder/internal/pkg/ds"
)

type Repository struct{ path string }

func NewRepository(path string) *Repository {
	return &Repository{path: path}
}

// Save stages a complete file before replacing the previous catalog.
func (r *Repository) Save(ctx context.Context, catalog ds.Catalog) error {
	return r.saveJSON(ctx, catalog)
}

func (r *Repository) SaveReport(ctx context.Context, report ds.CheckReport) error {
	return r.saveJSON(ctx, report)
}

func (r *Repository) Load(ctx context.Context) (ds.Catalog, error) {
	var catalog ds.Catalog
	if err := r.loadJSON(ctx, &catalog); err != nil {
		return ds.Catalog{}, err
	}
	if catalog.SchemaVersion != 1 {
		return ds.Catalog{}, fmt.Errorf("unsupported catalog schema %d", catalog.SchemaVersion)
	}
	return catalog, nil
}

func (r *Repository) LoadReport(ctx context.Context) (ds.CheckReport, error) {
	var report ds.CheckReport
	err := r.loadJSON(ctx, &report)
	return report, err
}

func (r *Repository) LoadState(ctx context.Context) (ds.BrowseState, bool, error) {
	var state ds.BrowseState
	err := r.loadJSON(ctx, &state)
	if errors.Is(err, os.ErrNotExist) {
		return state, false, nil
	}
	return state, true, err
}

func (r *Repository) SaveState(ctx context.Context, state ds.BrowseState) error {
	return r.saveJSON(ctx, state)
}

func (r *Repository) loadJSON(ctx context.Context, target any) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	file, err := os.Open(r.path)
	if err != nil {
		return fmt.Errorf("open JSON: %w", err)
	}
	defer file.Close()
	const maxSize = 8 << 20
	body, err := io.ReadAll(io.LimitReader(file, maxSize+1))
	if err != nil {
		return fmt.Errorf("read JSON: %w", err)
	}
	if len(body) > maxSize {
		return fmt.Errorf("JSON exceeds %d bytes", maxSize)
	}
	if err := json.Unmarshal(body, target); err != nil {
		return fmt.Errorf("decode JSON: %w", err)
	}
	return ctx.Err()
}

func (r *Repository) saveJSON(ctx context.Context, value any) (err error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	body, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Errorf("encode JSON: %w", err)
	}
	body = append(body, '\n')
	if err := os.MkdirAll(filepath.Dir(r.path), 0755); err != nil {
		return fmt.Errorf("create catalog directory: %w", err)
	}
	file, err := os.CreateTemp(filepath.Dir(r.path), ".resolvers-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary catalog: %w", err)
	}
	tempPath := file.Name()
	closed := false
	defer func() {
		if !closed {
			err = errors.Join(err, file.Close())
		}
		if cleanupErr := os.Remove(tempPath); cleanupErr != nil && !errors.Is(cleanupErr, os.ErrNotExist) {
			err = errors.Join(err, fmt.Errorf("remove temporary catalog: %w", cleanupErr))
		}
	}()
	if _, err = file.Write(body); err != nil {
		return fmt.Errorf("write temporary catalog: %w", err)
	}
	if err = file.Sync(); err != nil {
		return fmt.Errorf("sync temporary catalog: %w", err)
	}
	err = file.Close()
	closed = true
	if err != nil {
		return fmt.Errorf("close temporary catalog: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := os.Rename(tempPath, r.path); err != nil {
		return fmt.Errorf("replace catalog: %w", err)
	}
	return nil
}
