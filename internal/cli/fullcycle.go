package cli

import (
	"context"
	"errors"
	"fmt"
	"time"

	"doh-finder/internal/pkg/ds"
)

func (h *Handler) fullCycleMenu(ctx context.Context, choices <-chan menuInput, timeout time.Duration) error {
	if err := h.screen("FULL CYCLE - UPDATE SERVER LIST"); err != nil {
		return err
	}
	updateCtx, cancel := context.WithTimeout(ctx, timeout)
	err := h.Run(updateCtx)
	cancel()
	if err != nil {
		return err
	}
	if err := h.screen("FULL CYCLE - CHECK SERVERS"); err != nil {
		return err
	}
	if err := h.Check(ctx); err != nil {
		return err
	}
	return h.browse(ctx, choices, true)
}

// BrowseOnce is used by the noninteractive commands. A successful command is
// an explicit confirmation, so the previous confirmed DNS is enabled as backup.
func (h *Handler) BrowseOnce(ctx context.Context, priorities []int, continueAfterLast, refreshed bool) (state ds.BrowseState, err error) {
	if h.browser == nil {
		return ds.BrowseState{}, fmt.Errorf("auto browsing is not configured")
	}
	defer func() {
		recoveryCtx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		if recoveryErr := h.browser.Recover(recoveryCtx); recoveryErr != nil {
			err = errors.Join(err, fmt.Errorf("restore unconfirmed DNS: %w", recoveryErr))
		}
	}()
	if continueAfterLast {
		if refreshed {
			state, err = h.browser.StartAfterLast(ctx, priorities)
		} else {
			state, err = h.browser.ResumeAfterLast(ctx)
		}
	} else {
		state, err = h.browser.Start(ctx, priorities)
	}
	if err != nil {
		return state, err
	}
	checkCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	var outputErr error
	state, err = h.browser.TryNext(checkCtx, func(message string) {
		if outputErr == nil {
			_, outputErr = fmt.Fprintln(h.output, message)
			if outputErr != nil {
				cancel()
			}
		}
	})
	if outputErr != nil {
		return state, fmt.Errorf("write browse progress: %w", outputErr)
	}
	if err != nil {
		return state, err
	}
	state, err = h.browser.Confirm(ctx)
	if err != nil {
		return state, err
	}
	_, err = fmt.Fprintf(h.output, "Active DNS: %s (%s) | DoH: %s\n", state.LastWorking.Name, state.LastWorking.IP, state.LastWorking.DoHURL)
	if err == nil && state.Backup != nil {
		_, err = fmt.Fprintf(h.output, "Backup DNS: %s (%s) | DoH: %s\n", state.Backup.Name, state.Backup.IP, state.Backup.DoHURL)
	}
	return state, err
}

// FullCycle runs the same update, basic check, and browse services as menu
// options 1, 2 and 3, stopping at the first system-verified server.
func (h *Handler) FullCycle(ctx context.Context, timeout time.Duration, priorities []int, continueAfterLast bool) error {
	updateCtx, cancel := context.WithTimeout(ctx, timeout)
	err := h.Run(updateCtx)
	cancel()
	if err != nil {
		return fmt.Errorf("update server list: %w", err)
	}
	if err := h.Check(ctx); err != nil {
		return fmt.Errorf("check server list: %w", err)
	}
	if _, err := h.BrowseOnce(ctx, priorities, continueAfterLast, true); err != nil {
		return fmt.Errorf("browse checked servers: %w", err)
	}
	return nil
}
