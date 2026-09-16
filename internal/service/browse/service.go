package browse

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"sort"
	"time"

	"doh-finder/internal/pkg/ds"
)

type Service struct {
	reports ReportRepository
	states  StateRepository
	system  SystemDNS
}

func NewService(reports ReportRepository, states StateRepository, system SystemDNS) *Service {
	return &Service{reports: reports, states: states, system: system}
}

func validPriorities(priorities []int) bool {
	if len(priorities) != 3 {
		return false
	}
	seen := [4]bool{}
	for _, p := range priorities {
		if p < 1 || p > 3 || seen[p] {
			return false
		}
		seen[p] = true
	}
	return true
}

func usable(r ds.ServerResult) bool {
	ip, err := netip.ParseAddr(r.IP)
	if err != nil || !ip.Is4() || !r.Success || r.TCP.Status != "SUCCESS" || len(r.DNS) == 0 {
		return false
	}
	u, err := url.Parse(r.DoHURL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
		return false
	}
	if host, err := netip.ParseAddr(u.Hostname()); err == nil && host != ip {
		return false
	}
	for _, q := range r.DNS {
		if q.Status != "SUCCESS" || q.ElapsedMS < 0 {
			return false
		}
	}
	return true
}

func (s *Service) Load(ctx context.Context) (ds.BrowseState, bool, error) {
	state, exists, err := s.states.LoadState(ctx)
	if err != nil || !exists {
		return state, exists, err
	}
	if state.SchemaVersion != 1 || !validPriorities(state.Priorities) || len(state.Queue) == 0 || state.Current < -1 || state.Current >= len(state.Queue) || state.Verified && (state.Pending == nil || state.Current < 0) {
		return ds.BrowseState{}, true, fmt.Errorf("invalid saved browsing state")
	}
	seen := make(map[string]bool)
	for _, r := range state.Queue {
		key := r.IP + "\n" + r.DoHURL
		if !usable(r) || seen[key] {
			return ds.BrowseState{}, true, fmt.Errorf("invalid or duplicate server in saved queue")
		}
		seen[key] = true
	}
	if state.LastWorking != nil && !usable(*state.LastWorking) || state.Backup != nil && !usable(*state.Backup) {
		return ds.BrowseState{}, true, fmt.Errorf("invalid confirmed server in saved state")
	}
	return state, true, nil
}

func property(r ds.ServerResult, priority int) bool {
	switch priority {
	case 1:
		return r.Properties.NoFilter
	case 2:
		return r.Properties.NoLog
	default:
		return r.Properties.DNSSEC
	}
}

// Average DoH response time breaks ties between servers with identical properties.
func latency(r ds.ServerResult) float64 {
	var sum float64
	for _, q := range r.DNS {
		sum += float64(q.ElapsedMS)
	}
	return sum / float64(len(r.DNS))
}

func (s *Service) Start(ctx context.Context, priorities []int) (ds.BrowseState, error) {
	return s.start(ctx, priorities, false)
}

// StartAfterLast rebuilds the queue from the latest report and advances past
// the last confirmed server, identified by its explicit IPv4 and DoH URL.
func (s *Service) StartAfterLast(ctx context.Context, priorities []int) (ds.BrowseState, error) {
	return s.start(ctx, priorities, true)
}

// ResumeAfterLast reuses the saved queue and rewinds to the last confirmed
// server. Failed later attempts are retried on the next TryNext call.
func (s *Service) ResumeAfterLast(ctx context.Context) (ds.BrowseState, error) {
	if err := s.Recover(ctx); err != nil {
		return ds.BrowseState{}, err
	}
	state, exists, err := s.Load(ctx)
	if err != nil {
		return ds.BrowseState{}, err
	}
	if !exists || state.LastWorking == nil {
		return ds.BrowseState{}, fmt.Errorf("no previously confirmed server to continue after")
	}
	for i, candidate := range state.Queue {
		if candidate.IP == state.LastWorking.IP && candidate.DoHURL == state.LastWorking.DoHURL {
			state.Current = i
			return s.save(ctx, state)
		}
	}
	return ds.BrowseState{}, fmt.Errorf("last confirmed server is absent from the saved queue; use --start-over")
}

func (s *Service) start(ctx context.Context, priorities []int, afterLast bool) (ds.BrowseState, error) {
	if !validPriorities(priorities) {
		return ds.BrowseState{}, fmt.Errorf("priorities must contain 1, 2 and 3 exactly once")
	}
	if err := s.Recover(ctx); err != nil {
		return ds.BrowseState{}, err
	}
	previous, _, err := s.Load(ctx)
	if err != nil {
		return ds.BrowseState{}, err
	}
	if afterLast && previous.LastWorking == nil {
		return ds.BrowseState{}, fmt.Errorf("no previously confirmed server to continue after")
	}
	report, err := s.reports.LoadReport(ctx)
	if err != nil {
		return ds.BrowseState{}, fmt.Errorf("load successful servers (run option 2 first): %w", err)
	}
	queue := make([]ds.ServerResult, 0, len(report.Results))
	seen := make(map[string]bool)
	for _, r := range report.Results {
		key := r.IP + "\n" + r.DoHURL
		if usable(r) && !seen[key] {
			queue = append(queue, r)
			seen[key] = true
		}
	}
	if len(queue) == 0 {
		return ds.BrowseState{}, fmt.Errorf("no successful IPv4 servers; run option 2 first")
	}
	sort.SliceStable(queue, func(i, j int) bool {
		a, b := queue[i], queue[j]
		for _, priority := range priorities {
			if av, bv := property(a, priority), property(b, priority); av != bv {
				return av
			}
		}
		return latency(a) < latency(b)
	})
	state := ds.BrowseState{SchemaVersion: 1, Priorities: append([]int(nil), priorities...), Queue: queue, Current: -1, LastWorking: previous.LastWorking, Backup: previous.Backup}
	if afterLast {
		found := false
		for i, candidate := range queue {
			if candidate.IP == previous.LastWorking.IP && candidate.DoHURL == previous.LastWorking.DoHURL {
				state.Current = i
				found = true
				break
			}
		}
		if !found {
			return ds.BrowseState{}, fmt.Errorf("last confirmed server is absent from the newly checked list; use --start-over")
		}
	}
	return s.save(ctx, state)
}

// Recover also handles a previous process exiting during an unconfirmed trial.
func (s *Service) Recover(ctx context.Context) error {
	state, exists, err := s.Load(ctx)
	if err != nil || !exists {
		return err
	}
	if state.Pending == nil {
		return nil
	}
	return s.rollback(state)
}

func (s *Service) rollback(state ds.BrowseState) error {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	if err := s.system.Restore(ctx, *state.Pending); err != nil {
		return fmt.Errorf("restore previous DNS failed; recovery information is saved, retry option 3 as Administrator: %w", err)
	}
	state.Pending, state.Verified = nil, false
	_, err := s.save(ctx, state)
	return err
}

func (s *Service) TryNext(ctx context.Context, progress func(string)) (ds.BrowseState, error) {
	if err := s.Recover(ctx); err != nil {
		return ds.BrowseState{}, err
	}
	state, exists, err := s.Load(ctx)
	if err != nil {
		return ds.BrowseState{}, err
	}
	if !exists {
		return ds.BrowseState{}, fmt.Errorf("no saved queue; start a new session")
	}
	for state.Current+1 < len(state.Queue) {
		if err := ctx.Err(); err != nil {
			return state, err
		}
		candidate := state.Queue[state.Current+1]
		touched := []ds.ServerResult{candidate}
		if state.LastWorking != nil {
			touched = append(touched, *state.LastWorking)
		}
		snapshot, err := s.system.Snapshot(ctx, touched)
		if err != nil {
			return state, err
		}
		state.Current++
		state.Pending = &snapshot
		state.Verified = false
		// Journal is durable before the first OS setting is changed.
		if _, err := s.save(ctx, state); err != nil {
			return state, err
		}
		if progress != nil {
			progress(fmt.Sprintf("Testing %d/%d: %s (%s) on %s; no backup DNS", state.Current+1, len(state.Queue), candidate.Name, candidate.IP, snapshot.InterfaceName))
		}
		err = s.system.Apply(ctx, snapshot, candidate, nil)
		if err == nil {
			err = s.system.Verify(ctx, snapshot, candidate)
		}
		if err != nil {
			if rollbackErr := s.rollback(state); rollbackErr != nil {
				return state, errors.Join(err, rollbackErr)
			}
			state.Pending = nil
			if ctx.Err() != nil {
				return state, ctx.Err()
			}
			if progress != nil {
				progress("Failed: " + err.Error() + ". Previous settings restored.")
			}
			continue
		}
		state.Verified = true
		if _, err := s.save(ctx, state); err != nil {
			return state, errors.Join(err, s.rollback(state))
		}
		return state, nil
	}
	return state, fmt.Errorf("end of queue reached; previous DNS settings are active")
}

// Confirm is the only operation that enables a backup and updates LastWorking.
func (s *Service) Confirm(ctx context.Context) (ds.BrowseState, error) {
	state, exists, err := s.Load(ctx)
	if err != nil {
		return state, err
	}
	if !exists || !state.Verified || state.Pending == nil {
		return state, fmt.Errorf("no verified server awaiting confirmation")
	}
	primary := state.Queue[state.Current]
	backup := state.LastWorking
	if backup != nil && backup.IP == primary.IP {
		backup = nil
	}
	if err := s.system.Apply(ctx, *state.Pending, primary, backup); err != nil {
		return state, errors.Join(err, s.rollback(state))
	}
	committed := state
	committed.LastWorking, committed.Backup = &primary, backup
	committed.Pending, committed.Verified = nil, false
	if _, err := s.save(ctx, committed); err != nil {
		return state, errors.Join(err, s.rollback(state))
	}
	return committed, nil
}

func (s *Service) save(ctx context.Context, state ds.BrowseState) (ds.BrowseState, error) {
	state.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	if err := s.states.SaveState(ctx, state); err != nil {
		return ds.BrowseState{}, fmt.Errorf("save browsing state: %w", err)
	}
	return state, nil
}
