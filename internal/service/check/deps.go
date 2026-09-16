package check

import (
	"context"
	"doh-finder/internal/pkg/ds"
)

type CatalogRepository interface {
	Load(context.Context) (ds.Catalog, error)
}

type ReportRepository interface {
	SaveReport(context.Context, ds.CheckReport) error
}

type Prober interface {
	Check(context.Context, ds.Resolver) ds.ServerResult
}
