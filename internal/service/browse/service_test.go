package browse

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"testing"

	"doh-finder/internal/pkg/ds"
)

type memory struct {
	report   ds.CheckReport
	state    []byte
	failSave bool
}

func (m *memory) LoadReport(context.Context) (ds.CheckReport, error) { return m.report, nil }
func (m *memory) LoadState(context.Context) (ds.BrowseState, bool, error) {
	var state ds.BrowseState
	if m.state == nil {
		return state, false, nil
	}
	err := json.Unmarshal(m.state, &state)
	return state, true, err
}
func (m *memory) SaveState(ctx context.Context, state ds.BrowseState) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if m.failSave {
		return errors.New("disk full")
	}
	var err error
	m.state, err = json.Marshal(state)
	return err
}

type fakeSystem struct {
	store        *memory
	current      string
	events       []string
	fail         map[string]bool
	failRestore  bool
	failPair     bool
	onVerify     func()
	confirmed    bool
	routeChanged bool
}

func (f *fakeSystem) Snapshot(context.Context, []ds.ServerResult) (ds.DNSSnapshot, error) {
	f.events = append(f.events, "snapshot:"+f.current)
	return ds.DNSSnapshot{InterfaceIndex: 14, InterfaceGUID: "ethernet-guid", InterfaceName: "Ethernet", NameServer: f.current, Automatic: f.current == ""}, nil
}
func (f *fakeSystem) Apply(ctx context.Context, snap ds.DNSSnapshot, r ds.ServerResult, backup *ds.ServerResult) error {
	if f.routeChanged {
		return ds.ErrActiveInterfaceChanged
	}
	if snap.InterfaceGUID != "ethernet-guid" {
		return errors.New("changed another adapter")
	}
	state, _, err := f.store.LoadState(ctx)
	if err != nil || state.Pending == nil {
		return errors.New("mutation without durable recovery journal")
	}
	if backup != nil && !f.confirmed {
		return errors.New("backup set without user confirmation")
	}
	f.current = r.IP
	if backup != nil {
		f.current += "," + backup.IP
	}
	f.events = append(f.events, "apply:"+f.current)
	if f.failPair && backup != nil {
		return errors.New("pair apply failed")
	}
	return nil
}
func (f *fakeSystem) Verify(ctx context.Context, _ ds.DNSSnapshot, r ds.ServerResult) error {
	if f.current != r.IP {
		return errors.New("backup present during verification")
	}
	f.events = append(f.events, "verify:"+r.IP)
	if f.onVerify != nil {
		f.onVerify()
	}
	if f.routeChanged {
		return ds.ErrActiveInterfaceChanged
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if f.fail[r.IP] {
		return errors.New("website unavailable")
	}
	return nil
}
func (f *fakeSystem) Restore(ctx context.Context, snapshot ds.DNSSnapshot) error {
	if snapshot.InterfaceGUID != "ethernet-guid" {
		return errors.New("restored another adapter")
	}
	if ctx.Err() != nil {
		return errors.New("rollback inherited cancelled context")
	}
	f.events = append(f.events, "restore:"+snapshot.NameServer)
	if f.failRestore {
		return errors.New("restore failed")
	}
	f.current = snapshot.NameServer
	return nil
}

func server(i int, props ds.Properties, ms int64) ds.ServerResult {
	return ds.ServerResult{Name: fmt.Sprintf("server-%d", i), IP: fmt.Sprintf("192.0.2.%d", i), DoHURL: "https://dns.example/dns-query", Properties: props, Success: true,
		TCP: ds.ProbeResult{Status: "SUCCESS"}, DNS: []ds.DNSResult{{ProbeResult: ds.ProbeResult{Status: "SUCCESS", ElapsedMS: ms}, Domain: "example.com"}}}
}
func setup() (*Service, *memory, *fakeSystem) {
	m := &memory{report: ds.CheckReport{Results: []ds.ServerResult{server(1, ds.Properties{}, 10), server(2, ds.Properties{}, 20), server(3, ds.Properties{}, 30)}}}
	for i := 4; i <= 6; i++ {
		m.report.Results = append(m.report.Results, server(i, ds.Properties{}, int64(i*10)))
	}
	f := &fakeSystem{store: m, current: "original-primary,original-backup", fail: map[string]bool{}}
	return NewService(m, m, f), m, f
}

func TestPrioritiesThenLatencyDeduplicationAndResume(t *testing.T) {
	s, m, _ := setup()
	a := server(1, ds.Properties{NoFilter: true}, 30)
	b := server(2, ds.Properties{NoLog: true}, 1)
	c := server(3, ds.Properties{NoFilter: true}, 10)
	d := server(4, ds.Properties{NoFilter: true, NoLog: true, DNSSEC: true}, 100)
	failed := server(5, ds.Properties{}, 1)
	failed.Success = false
	m.report.Results = []ds.ServerResult{b, a, c, c, failed, d}
	for _, tc := range []struct {
		p    []int
		want []string
	}{
		{[]int{1, 2, 3}, []string{d.Name, c.Name, a.Name, b.Name}},
		{[]int{2, 1, 3}, []string{d.Name, b.Name, c.Name, a.Name}},
	} {
		state, err := s.Start(context.Background(), tc.p)
		if err != nil {
			t.Fatal(err)
		}
		names := []string{}
		for _, r := range state.Queue {
			names = append(names, r.Name)
		}
		if !reflect.DeepEqual(names, tc.want) {
			t.Fatalf("order %v want %v", names, tc.want)
		}
	}
	before, _, _ := s.Load(context.Background())
	m.report.Results = nil
	restarted := NewService(m, m, s.system)
	after, exists, err := restarted.Load(context.Background())
	if err != nil || !exists || !reflect.DeepEqual(before, after) {
		t.Fatal("updated report changed saved queue")
	}
}

func TestBackupOnlyAfterConfirmationAndResumeAdvances(t *testing.T) {
	s, m, f := setup()
	ctx := context.Background()
	if _, err := s.Start(ctx, []int{1, 2, 3}); err != nil {
		t.Fatal(err)
	}
	trial, err := s.TryNext(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if trial.LastWorking != nil || trial.Pending == nil || !trial.Verified {
		t.Fatal("trial incorrectly committed")
	}
	if trial.TrialPrimary.IP != "192.0.2.1" || trial.TrialBackup.IP != "192.0.2.2" || f.current != "192.0.2.1" || trial.Current != 1 {
		t.Fatal("did not independently find two servers while leaving primary alone")
	}
	f.confirmed = true
	first, err := s.Confirm(ctx)
	if err != nil || first.Backup.IP != "192.0.2.2" || first.LastWorking.IP != "192.0.2.1" || f.current != "192.0.2.1,192.0.2.2" {
		t.Fatalf("first confirmation: %+v %v", first, err)
	}
	f.confirmed = false
	s = NewService(m, m, f) // another process, same durable state
	trial, err = s.TryNext(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if trial.Current != 3 || f.current != "192.0.2.3" || trial.LastWorking.IP != "192.0.2.1" {
		t.Fatalf("resume/backup isolation failed: %+v", trial)
	}
	f.confirmed = true
	second, err := s.Confirm(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if second.LastWorking.IP != "192.0.2.3" || second.Backup.IP != "192.0.2.4" || f.current != "192.0.2.3,192.0.2.4" || second.Pending != nil {
		t.Fatal("wrong confirmed pair")
	}
}

func TestAllFailuresRestoreOriginalIncludingAutomaticDNS(t *testing.T) {
	for _, original := range []string{"original-primary,original-backup", ""} {
		s, _, f := setup()
		f.current = original
		for i := 1; i <= 6; i++ {
			f.fail[fmt.Sprintf("192.0.2.%d", i)] = true
		}
		ctx := context.Background()
		if _, err := s.Start(ctx, []int{1, 2, 3}); err != nil {
			t.Fatal(err)
		}
		state, err := s.TryNext(ctx, nil)
		if err == nil || f.current != original {
			t.Fatalf("did not restore original: %q %v", f.current, err)
		}
		if state.Current != 5 {
			t.Fatal("did not exhaust queue")
		}
		saved, _, _ := s.Load(ctx)
		if saved.Pending != nil || saved.LastWorking != nil {
			t.Fatal("failed server retained")
		}
	}
}

func TestCrashAndCancellationRecoverWithoutConfirming(t *testing.T) {
	for _, cancelRun := range []bool{false, true} {
		s, m, f := setup()
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		if _, err := s.Start(ctx, []int{1, 2, 3}); err != nil {
			t.Fatal(err)
		}
		if cancelRun {
			f.onVerify = cancel
		}
		_, err := s.TryNext(ctx, nil)
		if cancelRun && !errors.Is(err, context.Canceled) {
			t.Fatalf("lost cancellation: %v", err)
		}
		if err := NewService(m, m, f).Recover(context.Background()); err != nil {
			t.Fatal(err)
		}
		if f.current != "original-primary,original-backup" {
			t.Fatal("recovery did not restore snapshot")
		}
	}
}

func TestPersistenceFailureBeforeMutationAndFailedRollbackJournal(t *testing.T) {
	s, m, f := setup()
	ctx := context.Background()
	if _, err := s.Start(ctx, []int{1, 2, 3}); err != nil {
		t.Fatal(err)
	}
	m.failSave = true
	if _, err := s.TryNext(ctx, nil); err == nil {
		t.Fatal("ignored save failure")
	}
	if f.current != "original-primary,original-backup" {
		t.Fatal("mutated before journal")
	}
	m.failSave = false
	f.fail["192.0.2.1"], f.failRestore = true, true
	if _, err := s.TryNext(ctx, nil); err == nil {
		t.Fatal("ignored restore failure")
	}
	state, _, _ := s.Load(ctx)
	if state.Pending == nil {
		t.Fatal("lost recovery journal")
	}
	if state.Current != 0 {
		t.Fatal("continued after rollback failure")
	}
	f.failRestore = false
	if err := s.Recover(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestFailedConfirmationRestoresPreviouslyWorkingPair(t *testing.T) {
	s, _, f := setup()
	ctx := context.Background()
	s.Start(ctx, []int{1, 2, 3})
	s.TryNext(ctx, nil)
	f.confirmed = true
	if _, err := s.Confirm(ctx); err != nil {
		t.Fatal(err)
	}
	s.TryNext(ctx, nil)
	f.failPair = true
	if _, err := s.Confirm(ctx); err == nil {
		t.Fatal("ignored pair failure")
	}
	state, _, _ := s.Load(ctx)
	if state.LastWorking.IP != "192.0.2.1" || f.current != "192.0.2.1,192.0.2.2" || state.Pending != nil {
		t.Fatal("failed confirmation changed working DNS")
	}
}

func TestSaveFailureAfterVerificationRestoresNetworkAndKeepsJournal(t *testing.T) {
	s, m, f := setup()
	ctx := context.Background()
	if _, err := s.Start(ctx, []int{1, 2, 3}); err != nil {
		t.Fatal(err)
	}
	f.onVerify = func() { m.failSave = true }
	if _, err := s.TryNext(ctx, nil); err == nil {
		t.Fatal("ignored post-mutation save failure")
	}
	if f.current != "original-primary,original-backup" {
		t.Fatal("save failure left trial settings active")
	}
	state, _, _ := s.Load(ctx)
	if state.Pending == nil {
		t.Fatal("recovery journal vanished without a successful save")
	}
	m.failSave = false
	if err := s.Recover(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestInvalidInputsDoNotReplaceState(t *testing.T) {
	s, m, _ := setup()
	ctx := context.Background()
	if _, err := s.Start(ctx, []int{1, 2, 3}); err != nil {
		t.Fatal(err)
	}
	before := string(m.state)
	for _, p := range [][]int{{1, 1, 2}, {3, 2}, {0, 1, 2}} {
		if _, err := s.Start(ctx, p); err == nil {
			t.Fatal("accepted invalid priorities")
		}
	}
	m.report.Results = nil
	if _, err := s.Start(ctx, []int{1, 2, 3}); err == nil {
		t.Fatal("accepted empty report")
	}
	if string(m.state) != before {
		t.Fatal("failed start overwrote state")
	}
	m.state = []byte(`{"schemaVersion":1,"priorities":[1,2,3],"current":99,"queue":[]}`)
	if _, _, err := s.Load(ctx); err == nil {
		t.Fatal("accepted corrupt state")
	}
}

func TestContinueAfterLastConfirmedWithFreshAndSavedQueues(t *testing.T) {
	s, m, f := setup()
	ctx := context.Background()
	if _, err := s.Start(ctx, []int{1, 2, 3}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.TryNext(ctx, nil); err != nil {
		t.Fatal(err)
	}
	f.confirmed = true
	if _, err := s.Confirm(ctx); err != nil {
		t.Fatal(err)
	}
	// A later failed trial must not become the continuation point.
	f.fail["192.0.2.3"] = true
	if _, err := s.TryNext(ctx, nil); err != nil {
		t.Fatal(err)
	}
	before, _, _ := s.Load(ctx)
	if before.Current != 4 || before.LastWorking.IP != "192.0.2.1" {
		t.Fatal("bad setup")
	}
	saved, err := s.ResumeAfterLast(ctx)
	if err != nil || saved.Current != 1 {
		t.Fatalf("saved queue did not rewind to last success: %+v %v", saved, err)
	}
	// Freshly checked results may have different timings and therefore a new order.
	m.report.Results = []ds.ServerResult{server(3, ds.Properties{}, 1), server(2, ds.Properties{}, 2), server(1, ds.Properties{}, 3)}
	refreshed, err := s.StartAfterLast(ctx, []int{1, 2, 3})
	if err != nil || refreshed.Current != 1 || refreshed.Queue[1].IP != "192.0.2.2" {
		t.Fatalf("fresh queue position=%+v %v", refreshed, err)
	}
	if !reflect.DeepEqual(refreshed.Priorities, []int{1, 2, 3}) {
		t.Fatal("priorities lost")
	}
	priorState := string(m.state)
	m.report.Results = []ds.ServerResult{server(3, ds.Properties{}, 1)}
	if _, err := s.StartAfterLast(ctx, []int{1, 2, 3}); err == nil {
		t.Fatal("missing anchor accepted")
	}
	if string(m.state) != priorState {
		t.Fatal("missing anchor overwrote saved queue")
	}
}

func TestPairSkipsFailedAndDuplicateAddresses(t *testing.T) {
	s, m, f := setup()
	a := server(1, ds.Properties{}, 1)
	duplicate := a
	duplicate.DoHURL = "https://other.example/dns-query"
	duplicate.DNS[0].ElapsedMS = 1
	m.report.Results = []ds.ServerResult{a, duplicate, server(2, ds.Properties{}, 2), server(3, ds.Properties{}, 3)}
	f.fail["192.0.2.2"] = true
	ctx := context.Background()
	if _, err := s.Start(ctx, []int{1, 2, 3}); err != nil {
		t.Fatal(err)
	}
	state, err := s.TryNext(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if state.TrialPrimary.IP != a.IP || state.TrialBackup.IP != "192.0.2.3" {
		t.Fatal("wrong pair")
	}
	want := []string{"snapshot:original-primary,original-backup", "apply:192.0.2.1", "verify:192.0.2.1", "apply:192.0.2.2", "verify:192.0.2.2", "restore:original-primary,original-backup", "apply:192.0.2.3", "verify:192.0.2.3", "apply:192.0.2.1", "verify:192.0.2.1"}
	if !reflect.DeepEqual(f.events, want) {
		t.Fatalf("isolation/order: %v", f.events)
	}
}

func TestNoSecondServerRestoresOriginalAndDoesNotConfirm(t *testing.T) {
	for _, duplicateOnly := range []bool{false, true} {
		s, m, f := setup()
		if duplicateOnly {
			a := server(1, ds.Properties{}, 1)
			b := a
			b.DoHURL = "https://other.example/dns-query"
			m.report.Results = []ds.ServerResult{a, b}
		} else {
			for i := 2; i <= 6; i++ {
				f.fail[fmt.Sprintf("192.0.2.%d", i)] = true
			}
		}
		ctx := context.Background()
		if _, err := s.Start(ctx, []int{1, 2, 3}); err != nil {
			t.Fatal(err)
		}
		if _, err := s.TryNext(ctx, nil); err == nil {
			t.Fatal("accepted incomplete pair")
		}
		if f.current != "original-primary,original-backup" {
			t.Fatal("did not restore original settings")
		}
		state, _, err := s.Load(ctx)
		if err != nil || state.Pending != nil || state.TrialPrimary != nil || state.TrialBackup != nil || state.LastWorking != nil {
			t.Fatalf("retained failed trial: %+v %v", state, err)
		}
		if _, err := s.Confirm(ctx); err == nil {
			t.Fatal("confirmed incomplete pair")
		}
	}
}

func TestRouteChangeDuringTrialOrConfirmationRestoresOriginalInterface(t *testing.T) {
	for _, duringTrial := range []bool{true, false} {
		s, _, f := setup()
		ctx := context.Background()
		if _, err := s.Start(ctx, []int{1, 2, 3}); err != nil {
			t.Fatal(err)
		}
		if duringTrial {
			f.onVerify = func() { f.routeChanged = true }
		}
		_, err := s.TryNext(ctx, nil)
		if !duringTrial {
			if err != nil {
				t.Fatal(err)
			}
			f.routeChanged = true
			_, err = s.Confirm(ctx)
		}
		if !errors.Is(err, ds.ErrActiveInterfaceChanged) {
			t.Fatalf("lost route change: %v", err)
		}
		if f.current != "original-primary,original-backup" {
			t.Fatal("did not restore original interface")
		}
		state, _, err := s.Load(ctx)
		if err != nil || state.Pending != nil || state.LastWorking != nil {
			t.Fatal("committed a pair across interfaces")
		}
	}
}

func TestLegacySingleServerJournalCanStillBeRecovered(t *testing.T) {
	s, m, f := setup()
	ctx := context.Background()
	state, err := s.Start(ctx, []int{1, 2, 3})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, _ := f.Snapshot(ctx, nil)
	state.Current, state.Pending, state.Verified = 0, &snapshot, true
	if err := m.SaveState(ctx, state); err != nil {
		t.Fatal(err)
	}
	f.current = state.Queue[0].IP
	if err := s.Recover(ctx); err != nil {
		t.Fatal(err)
	}
	if f.current != snapshot.NameServer {
		t.Fatal("lost legacy recovery")
	}
}

func TestCancellationAtEveryStageRestoresOriginalPair(t *testing.T) {
	for _, stage := range []int{1, 2, 3} {
		t.Run(fmt.Sprint(stage), func(t *testing.T) {
			s, _, f := setup()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if _, err := s.Start(ctx, []int{1, 2, 3}); err != nil {
				t.Fatal(err)
			}
			calls := 0
			f.onVerify = func() {
				calls++
				if calls == stage {
					cancel()
				}
			}
			if _, err := s.TryNext(ctx, nil); !errors.Is(err, context.Canceled) {
				t.Fatalf("stage %d: %v", stage, err)
			}
			if f.current != "original-primary,original-backup" {
				t.Fatal("restored a trial instead of original settings")
			}
		})
	}
}

func TestPrimaryFailureOnFinalCheckContinuesSearching(t *testing.T) {
	s, _, f := setup()
	ctx := context.Background()
	if _, err := s.Start(ctx, []int{1, 2, 3}); err != nil {
		t.Fatal(err)
	}
	calls := 0
	f.onVerify = func() {
		calls++
		if calls == 3 {
			f.fail["192.0.2.1"] = true
		}
	}
	state, err := s.TryNext(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if state.TrialPrimary.IP != "192.0.2.2" || state.TrialBackup.IP != "192.0.2.3" || f.current != "192.0.2.2" {
		t.Fatalf("did not replace the failed primary: %+v", state)
	}
}

func TestConfirmationSaveFailureRestoresOriginalAndRetainsJournal(t *testing.T) {
	s, m, f := setup()
	ctx := context.Background()
	if _, err := s.Start(ctx, []int{1, 2, 3}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.TryNext(ctx, nil); err != nil {
		t.Fatal(err)
	}
	f.confirmed = true
	m.failSave = true
	if _, err := s.Confirm(ctx); err == nil {
		t.Fatal("ignored state write failure")
	}
	if f.current != "original-primary,original-backup" {
		t.Fatal("new pair remained after failed commit")
	}
	state, _, err := s.Load(ctx)
	if err != nil || state.Pending == nil || state.LastWorking != nil {
		t.Fatal("lost rollback journal or confirmed failed write")
	}
	m.failSave = false
	if err := s.Recover(ctx); err != nil {
		t.Fatal(err)
	}
}
