package cli

import (
	"context"
	"doh-finder/internal/pkg/ds"
)

type CatalogService interface {
	Update(context.Context) (ds.Catalog, error)
}

type CheckService interface {
	Run(context.Context, func(ds.CheckProgress)) (ds.CheckReport, error)
}

type BrowseService interface {
	Load(context.Context) (ds.BrowseState, bool, error)
	Start(context.Context, []int) (ds.BrowseState, error)
	StartAfterLast(context.Context, []int) (ds.BrowseState, error)
	ResumeAfterLast(context.Context) (ds.BrowseState, error)
	TryNext(context.Context, func(string)) (ds.BrowseState, error)
	Confirm(context.Context) (ds.BrowseState, error)
	Recover(context.Context) error
}
