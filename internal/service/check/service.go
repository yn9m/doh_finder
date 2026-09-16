package check

import (
	"context"
	"fmt"
	"sync"
	"time"

	"doh-finder/internal/pkg/ds"
)

type Service struct {
	catalog CatalogRepository
	reports ReportRepository
	prober  Prober
	workers int
	timeout time.Duration
	domains []string
}

func NewService(catalog CatalogRepository, reports ReportRepository, prober Prober, workers int, timeout time.Duration, domains []string) *Service {
	return &Service{catalog: catalog, reports: reports, prober: prober, workers: workers, timeout: timeout, domains: append([]string(nil), domains...)}
}

// Run limits active servers to workers. Only the collector modifies the report
// or invokes progress, so console output and result aggregation are serialized.
func (s *Service) Run(ctx context.Context, progress func(ds.CheckProgress)) (ds.CheckReport, error) {
	if s.workers < 1 || s.workers > 128 || s.timeout <= 0 {
		return ds.CheckReport{}, fmt.Errorf("invalid check settings")
	}
	catalog, err := s.catalog.Load(ctx)
	if err != nil {
		return ds.CheckReport{}, fmt.Errorf("load server list (use option 1 to create it): %w", err)
	}
	if len(catalog.Resolvers) == 0 {
		return ds.CheckReport{}, fmt.Errorf("server list is empty; use option 1 to update it")
	}
	report := ds.CheckReport{
		StartedAt: time.Now().UTC().Format(time.RFC3339), Source: catalog.Source,
		Workers: s.workers, TimeoutMS: s.timeout.Milliseconds(), Domains: s.domains,
		Results: make([]ds.ServerResult, len(catalog.Resolvers)),
	}
	type result struct {
		index int
		value ds.ServerResult
	}
	jobs := make(chan int)
	results := make(chan result, s.workers)
	var workers sync.WaitGroup
	for i := 0; i < min(s.workers, len(catalog.Resolvers)); i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for index := range jobs {
				if ctx.Err() != nil {
					return
				}
				value := s.prober.Check(ctx, catalog.Resolvers[index])
				results <- result{index, value}
			}
		}()
	}
	go func() {
		defer close(jobs)
		for index := range catalog.Resolvers {
			select {
			case jobs <- index:
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() { workers.Wait(); close(results) }()
	completed := 0
	for result := range results {
		result.value.Properties = catalog.Resolvers[result.index].Properties
		report.Results[result.index] = result.value
		completed++
		if progress != nil {
			progress(ds.CheckProgress{Completed: completed, Total: len(report.Results), Result: result.value})
		}
	}
	// Incomplete runs never replace the last complete report.
	if err := ctx.Err(); err != nil {
		return ds.CheckReport{}, err
	}
	report.Checked = completed
	passed := make([]ds.ServerResult, 0, completed)
	for _, result := range report.Results {
		if result.Success {
			passed = append(passed, result)
		}
	}
	report.Results = passed
	report.Failed = completed - len(passed)
	report.FinishedAt = time.Now().UTC().Format(time.RFC3339)
	if err := s.reports.SaveReport(ctx, report); err != nil {
		return report, fmt.Errorf("save check report: %w", err)
	}
	return report, nil
}
