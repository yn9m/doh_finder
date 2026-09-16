package check

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"doh-finder/internal/pkg/ds"
)

type catalogStub struct {
	catalog ds.Catalog
	err     error
}

func (s catalogStub) Load(context.Context) (ds.Catalog, error) { return s.catalog, s.err }

type reportStub struct {
	report ds.CheckReport
	calls  int
	err    error
}

func (r *reportStub) SaveReport(_ context.Context, report ds.CheckReport) error {
	r.report = report
	r.calls++
	return r.err
}

type probeFunc func(context.Context, ds.Resolver) ds.ServerResult

func (p probeFunc) Check(ctx context.Context, r ds.Resolver) ds.ServerResult { return p(ctx, r) }

func TestPoolBoundedParallelismAndOrderedReport(t *testing.T) {
	var active, peak atomic.Int32
	gate := make(chan struct{})
	started := make(chan struct{}, 3)
	probe := probeFunc(func(ctx context.Context, r ds.Resolver) ds.ServerResult {
		n := active.Add(1)
		for old := peak.Load(); n > old && !peak.CompareAndSwap(old, n); old = peak.Load() {
		}
		select {
		case started <- struct{}{}:
		default:
		}
		select {
		case <-gate:
		case <-ctx.Done():
		}
		active.Add(-1)
		return ds.ServerResult{Name: r.Name, Success: true}
	})
	catalog := ds.Catalog{SchemaVersion: 1}
	for i := 0; i < 10; i++ {
		catalog.Resolvers = append(catalog.Resolvers, ds.Resolver{Name: fmt.Sprint(i)})
	}
	reports := &reportStub{}
	service := NewService(catalogStub{catalog: catalog}, reports, probe, 3, time.Second, []string{"example.com"})
	done := make(chan error, 1)
	completed := 0
	go func() {
		_, err := service.Run(context.Background(), func(p ds.CheckProgress) {
			completed++
			if p.Completed != completed || p.Total != 10 {
				t.Errorf("bad progress: %+v", p)
			}
		})
		done <- err
	}()
	for i := 0; i < 3; i++ {
		select {
		case <-started:
		case <-time.After(time.Second):
			close(gate)
			t.Fatal("workers did not run concurrently")
		}
	}
	close(gate)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if peak.Load() != 3 || active.Load() != 0 || reports.calls != 1 || completed != 10 {
		t.Fatalf("pool or aggregation failed: peak=%d completed=%d", peak.Load(), completed)
	}
	for i, r := range reports.report.Results {
		if r.Name != fmt.Sprint(i) {
			t.Fatal("report order changed")
		}
	}
}

func TestCancellationDoesNotReplaceReport(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan struct{}, 1)
	probe := probeFunc(func(ctx context.Context, r ds.Resolver) ds.ServerResult {
		select {
		case started <- struct{}{}:
		default:
		}
		<-ctx.Done()
		return ds.ServerResult{}
	})
	reports := &reportStub{}
	service := NewService(catalogStub{catalog: ds.Catalog{Resolvers: []ds.Resolver{{}, {}, {}}}}, reports, probe, 1, time.Second, nil)
	done := make(chan error, 1)
	go func() { _, err := service.Run(ctx, nil); done <- err }()
	<-started
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation, got %v", err)
	}
	if reports.calls != 0 {
		t.Fatal("saved incomplete report")
	}
}

func TestReportKeepsOnlySuccessfulServersWithPropertiesAndTimings(t *testing.T) {
	for _, tc := range []struct {
		name   string
		passed []bool
	}{
		{"mixed", []bool{false, true, false, true}},
		{"all passed", []bool{true, true}},
		{"none passed", []bool{false, false}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			catalog := ds.Catalog{SchemaVersion: 1}
			wantNames := []string{}
			for i, passed := range tc.passed {
				ip := fmt.Sprintf("192.0.2.%d", i+1)
				name := fmt.Sprintf("server-%d", i)
				catalog.Resolvers = append(catalog.Resolvers, ds.Resolver{
					Name: name, IP: &ip, DoHURL: "https://example.com/dns-query",
					Properties: ds.Properties{NoFilter: i%2 == 1, NoLog: true, DNSSEC: i%2 == 0},
				})
				if passed {
					wantNames = append(wantNames, name)
				}
			}
			probe := probeFunc(func(_ context.Context, r ds.Resolver) ds.ServerResult {
				var i int
				fmt.Sscanf(r.Name, "server-%d", &i)
				return ds.ServerResult{
					Name: r.Name, IP: *r.IP, DoHURL: r.DoHURL, Success: tc.passed[i],
					TCP: ds.ProbeResult{ElapsedMS: 12},
					DNS: []ds.DNSResult{{Domain: "example.com", ProbeResult: ds.ProbeResult{ElapsedMS: 34}}},
				}
			})
			reports := &reportStub{}
			progressCount := 0
			report, err := NewService(catalogStub{catalog: catalog}, reports, probe, 3, time.Second, []string{"example.com"}).Run(context.Background(), func(p ds.CheckProgress) {
				progressCount++
				if p.Completed != progressCount || p.Total != len(tc.passed) {
					t.Errorf("incorrect progress: %+v", p)
				}
				for _, r := range catalog.Resolvers {
					if r.Name == p.Result.Name && r.Properties != p.Result.Properties {
						t.Errorf("lost properties in progress for %s", r.Name)
					}
				}
			})
			if err != nil {
				t.Fatal(err)
			}
			if report.Checked != len(tc.passed) || report.Failed != len(tc.passed)-len(wantNames) || progressCount != len(tc.passed) {
				t.Fatalf("incorrect counts: %+v, progress=%d", report, progressCount)
			}
			if reports.calls != 1 || !reflect.DeepEqual(report, reports.report) {
				t.Fatal("returned and saved reports differ")
			}
			gotNames := []string{}
			for _, r := range report.Results {
				gotNames = append(gotNames, r.Name)
				if !r.Success || r.TCP.ElapsedMS != 12 || len(r.DNS) != 1 || r.DNS[0].ElapsedMS != 34 {
					t.Fatalf("invalid retained result: %+v", r)
				}
				for _, source := range catalog.Resolvers {
					if source.Name == r.Name && (source.Properties != r.Properties || *source.IP != r.IP || source.DoHURL != r.DoHURL) {
						t.Errorf("lost metadata for %s", r.Name)
					}
				}
			}
			if !reflect.DeepEqual(gotNames, wantNames) {
				t.Fatalf("wrong successful results/order: got %v, want %v", gotNames, wantNames)
			}
			body, err := json.Marshal(reports.report)
			if err != nil {
				t.Fatal(err)
			}
			if len(wantNames) == 0 && !strings.Contains(string(body), `"results":[]`) {
				t.Fatalf("empty results must be an array: %s", body)
			}
			if len(catalog.Resolvers) != len(tc.passed) {
				t.Fatal("check modified the source catalog")
			}
		})
	}
}

func TestMissingListAndReportWriteFailure(t *testing.T) {
	want := errors.New("disk failure")
	probe := probeFunc(func(context.Context, ds.Resolver) ds.ServerResult { return ds.ServerResult{} })
	for _, catalog := range []catalogStub{{err: want}, {}} {
		reports := &reportStub{}
		_, err := NewService(catalog, reports, probe, 1, time.Second, nil).Run(context.Background(), nil)
		if err == nil || reports.calls != 0 {
			t.Fatal("invalid list accepted")
		}
	}
	reports := &reportStub{err: want}
	_, err := NewService(catalogStub{catalog: ds.Catalog{Resolvers: []ds.Resolver{{}}}}, reports, probe, 1, time.Second, nil).Run(context.Background(), nil)
	if !errors.Is(err, want) {
		t.Fatalf("lost report write error: %v", err)
	}
}
