//go:build !windows || !amd64

package systemdns

import (
	"context"
	"doh-finder/internal/pkg/ds"
	"fmt"
	"time"
)

type System struct{}

func NewSystem(time.Duration) *System { return &System{} }
func unsupported() error {
	return fmt.Errorf("native DNS configuration currently requires Windows x64 with DoH support")
}
func (*System) Snapshot(context.Context, []ds.ServerResult) (ds.DNSSnapshot, error) {
	return ds.DNSSnapshot{}, unsupported()
}
func (*System) Apply(context.Context, ds.DNSSnapshot, ds.ServerResult, *ds.ServerResult) error {
	return unsupported()
}
func (*System) Verify(context.Context, ds.DNSSnapshot, ds.ServerResult) error { return unsupported() }
func (*System) Restore(context.Context, ds.DNSSnapshot) error                 { return unsupported() }
func Resolve(int, string) ([]string, error)                                   { return nil, unsupported() }
func LockSession() (func(), error)                                            { return func() {}, nil }
