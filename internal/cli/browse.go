package cli

import (
	"context"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"time"

	"doh-finder/internal/pkg/ds"
)

func parsePriorities(line string) ([]int, error) {
	if strings.TrimSpace(line) == "" {
		return []int{1, 2, 3}, nil
	}
	fields := strings.Fields(line)
	if len(fields) != 3 {
		return nil, fmt.Errorf("enter 1, 2 and 3 once each, separated by spaces")
	}
	priorities := make([]int, 0, 3)
	seen := [4]bool{}
	for _, field := range fields {
		p, err := strconv.Atoi(field)
		if err != nil || p < 1 || p > 3 || seen[p] {
			return nil, fmt.Errorf("enter 1, 2 and 3 once each, separated by spaces")
		}
		seen[p] = true
		priorities = append(priorities, p)
	}
	return priorities, nil
}

func (h *Handler) priorities(ctx context.Context, choices <-chan menuInput) ([]int, error) {
	hint := ""
	for {
		if err := h.screen("AUTO BROWSE - PRIORITIES"); err != nil {
			return nil, err
		}
		if _, err := fmt.Fprintf(h.output, "1. NoFilter\n2. NoLog\n3. DNSSEC\n\nEnter priority order (e.g. 1 2 3 or 3 2 1).\nEnter = %s; 0 = Back.\n%sPriority order: ", priorityText(h.defaultPriorities), hint); err != nil {
			return nil, err
		}
		line, err := nextChoice(ctx, choices)
		if err != nil {
			return nil, err
		}
		if line == "0" {
			return nil, nil
		}
		if line == "" {
			return append([]int(nil), h.defaultPriorities...), nil
		}
		priorities, err := parsePriorities(line)
		if err == nil {
			return priorities, nil
		}
		hint = "Invalid order: " + err.Error() + ".\n\n"
	}
}

func (h *Handler) browse(ctx context.Context, choices <-chan menuInput, refreshed bool) (err error) {
	priorities, err := h.priorities(ctx, choices)
	if err != nil || priorities == nil {
		return err
	}
	if h.browser == nil {
		return fmt.Errorf("auto browsing is not configured")
	}
	state, exists, err := h.browser.Load(ctx)
	if err != nil {
		return err
	}
	defer func() {
		recoveryCtx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		if recoveryErr := h.browser.Recover(recoveryCtx); recoveryErr != nil {
			err = fmt.Errorf("DNS recovery failed: %w (operation: %v)", recoveryErr, err)
		}
	}()
	start := !exists
	if exists {
		hint := ""
		canContinue := !refreshed || state.LastWorking != nil
		for {
			if err := h.screen("AUTO BROWSE - SAVED SESSION"); err != nil {
				return err
			}
			if _, err := fmt.Fprintf(h.output, "Saved position: %d/%d. Priorities: %s\n", state.Current+1, len(state.Queue), priorityText(state.Priorities)); err != nil {
				return err
			}
			if !reflect.DeepEqual(priorities, state.Priorities) {
				message := "New priorities apply when starting over. Continue keeps the saved queue."
				if refreshed {
					message = "The fresh list uses these priorities for both Start over and Continue."
				}
				if _, err := fmt.Fprintln(h.output, message); err != nil {
					return err
				}
			}
			options := "\n1. Start over\n"
			if canContinue {
				options += "2. Continue\n"
			} else {
				options += "No confirmed server yet; the fresh list must start over.\n"
			}
			if _, err := fmt.Fprintf(h.output, "%s0. Back\n\n%sSelect an option: ", options, hint); err != nil {
				return err
			}
			choice, err := nextChoice(ctx, choices)
			if err != nil {
				return err
			}
			if choice == "0" {
				return nil
			}
			if choice == "1" || choice == "2" && canContinue {
				start = choice == "1"
				break
			}
			hint = "Invalid option.\n"
		}
	}
	if start {
		if _, err := h.browser.Start(ctx, priorities); err != nil {
			return err
		}
	} else if refreshed {
		if _, err := h.browser.StartAfterLast(ctx, priorities); err != nil {
			return err
		}
	}
	for {
		if err := h.screen("AUTO BROWSE - TESTING"); err != nil {
			return err
		}
		checkCtx, cancel := context.WithCancel(ctx)
		var outputErr error
		state, err = h.browser.TryNext(checkCtx, func(message string) {
			if outputErr == nil {
				_, outputErr = fmt.Fprintln(h.output, message)
				if outputErr != nil {
					cancel()
				}
			}
		})
		cancel()
		if outputErr != nil {
			return outputErr
		}
		if err != nil {
			return err
		}
		keep, back, err := h.confirmServer(ctx, choices, state)
		if err != nil {
			return err
		}
		if back {
			return nil
		}
		if !keep {
			continue
		}
		state, err = h.browser.Confirm(ctx)
		if err != nil {
			return err
		}
		if err := h.screen("AUTO BROWSE - SAVED"); err != nil {
			return err
		}
		if _, err := fmt.Fprintf(h.output, "Primary DNS: %s (%s)\nDoH: %s\n", state.LastWorking.Name, state.LastWorking.IP, state.LastWorking.DoHURL); err != nil {
			return err
		}
		if state.Backup != nil {
			_, err = fmt.Fprintf(h.output, "Backup DNS: %s (%s)\nDoH: %s\n", state.Backup.Name, state.Backup.IP, state.Backup.DoHURL)
		} else {
			_, err = fmt.Fprintln(h.output, "Backup DNS: none (no different previously confirmed server).")
		}
		if err != nil {
			return err
		}
		if _, err := fmt.Fprintln(h.output, "Settings and position saved. These DNS settings remain active after exit."); err != nil {
			return err
		}
		return h.pause(ctx, choices)
	}
}

func (h *Handler) confirmServer(ctx context.Context, choices <-chan menuInput, state ds.BrowseState) (keep, back bool, err error) {
	hint := ""
	for {
		if err := h.screen("AUTO BROWSE - SERVER WORKS"); err != nil {
			return false, false, err
		}
		r := state.Queue[state.Current]
		if _, err := fmt.Fprintf(h.output, "Server %d/%d: %s\nIPv4: %s\nDoH: %s\nNoFilter: %t | NoLog: %t | DNSSEC: %t\n\nWindows DNS and HTTPS checks passed.\nThis is the only DNS server on the adapter during this trial.\nYou can now check websites in your browser.\n\n1. Try next server\n2. Keep this server (confirm; add previous working DNS as backup)\n0. Back (restore previous settings)\n\n%sSelect an option: ", state.Current+1, len(state.Queue), r.Name, r.IP, r.DoHURL, r.Properties.NoFilter, r.Properties.NoLog, r.Properties.DNSSEC, hint); err != nil {
			return false, false, err
		}
		choice, err := nextChoice(ctx, choices)
		if err != nil {
			return false, false, err
		}
		switch choice {
		case "0":
			return false, true, nil
		case "1":
			return false, false, nil
		case "2":
			return true, false, nil
		default:
			hint = "Invalid option. Enter 1, 2 or 0.\n"
		}
	}
}
