package catalog

import (
	"context"
	"fmt"
	"sort"

	"doh-finder/internal/pkg/ds"
)

type Service struct {
	source     Source
	repository Repository
}

func NewService(source Source, repository Repository) *Service {
	return &Service{source: source, repository: repository}
}

func (s *Service) Update(ctx context.Context) (ds.Catalog, error) {
	result, err := s.source.Fetch(ctx)
	if err != nil {
		return ds.Catalog{}, fmt.Errorf("fetch resolver catalog: %w", err)
	}
	result.Resolvers, err = ipv4Resolvers(result.Resolvers)
	if err != nil {
		return ds.Catalog{}, fmt.Errorf("filter resolver catalog: %w", err)
	}
	if len(result.Resolvers) == 0 {
		return ds.Catalog{}, fmt.Errorf("source contains no eligible IPv4 DoH resolvers; existing catalog preserved")
	}
	sort.SliceStable(result.Resolvers, func(i, j int) bool {
		a, b := result.Resolvers[i], result.Resolvers[j]
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.Stamp < b.Stamp
	})
	result.SchemaVersion = 1
	if err := s.repository.Save(ctx, result); err != nil {
		return ds.Catalog{}, fmt.Errorf("save resolver catalog: %w", err)
	}
	return result, nil
}
