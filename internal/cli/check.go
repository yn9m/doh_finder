package cli

import (
	"context"
	"fmt"
	"strings"

	"doh-finder/internal/pkg/ds"
)

func (h *Handler) Check(ctx context.Context) error {
	if h.checker == nil {
		return fmt.Errorf("server checking is not configured")
	}
	if _, err := fmt.Fprintln(h.output, "Checking servers (IPv4 TCP + DNS over HTTPS)..."); err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var outputErr error
	report, err := h.checker.Run(ctx, func(progress ds.CheckProgress) {
		if outputErr != nil {
			return
		}
		r := progress.Result
		parts := make([]string, 0, len(r.DNS))
		for _, query := range r.DNS {
			parts = append(parts, fmt.Sprintf("%s=%s (%d ms)", query.Domain, query.Status, query.ElapsedMS))
		}
		_, outputErr = fmt.Fprintf(h.output, "[%d/%d] %s (%s) | NoFilter: %t | NoLog: %t | DNSSEC: %t | TCP: %s (%d ms) | DoH: %s\n",
			progress.Completed, progress.Total, r.Name, r.IP, r.Properties.NoFilter, r.Properties.NoLog, r.Properties.DNSSEC,
			r.TCP.Status, r.TCP.ElapsedMS, strings.Join(parts, "; "))
		if outputErr == nil && r.TCP.Error != "" {
			_, outputErr = fmt.Fprintf(h.output, "  TCP: %s\n", r.TCP.Error)
		}
		for _, query := range r.DNS {
			if outputErr == nil && query.Error != "" {
				_, outputErr = fmt.Fprintf(h.output, "  %s: %s\n", query.Domain, query.Error)
			}
		}
		if outputErr != nil {
			cancel()
		}
	})
	if outputErr != nil {
		return fmt.Errorf("write check progress: %w", outputErr)
	}
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(h.output, "\nCheck complete: %d/%d passed TCP and both DNS queries; %d with failures. Only successful servers are saved.\n",
		len(report.Results), report.Checked, report.Failed)
	return err
}
