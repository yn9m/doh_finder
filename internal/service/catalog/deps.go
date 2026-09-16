package catalog

import (
	"context"
	"doh-finder/internal/pkg/ds"
)

type Source interface {
	Fetch(context.Context) (ds.Catalog, error)
}

type Repository interface {
	Save(context.Context, ds.Catalog) error
}
