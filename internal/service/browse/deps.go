package browse

import (
	"context"

	"doh-finder/internal/pkg/ds"
)

type ReportRepository interface {
	LoadReport(context.Context) (ds.CheckReport, error)
}

type StateRepository interface {
	LoadState(context.Context) (ds.BrowseState, bool, error)
	SaveState(context.Context, ds.BrowseState) error
}

type SystemDNS interface {
	Snapshot(context.Context, []ds.ServerResult) (ds.DNSSnapshot, error)
	Apply(context.Context, ds.DNSSnapshot, ds.ServerResult, *ds.ServerResult) error
	Verify(context.Context, ds.DNSSnapshot, ds.ServerResult) error
	Restore(context.Context, ds.DNSSnapshot) error
}
