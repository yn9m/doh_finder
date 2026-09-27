package cli

import (
	"context"
	"fmt"
	"strings"
)

// Windows exposes adapter-wide and per-network Wi-Fi settings on different
// screens. We write only the former, which overrides the latter.
func (h *Handler) dnsSettingsLocation() error {
	_, err := fmt.Fprintln(h.output, "Scope: IPv4 DNS for the selected adapter.\nWi-Fi: view Windows Settings > Network & Internet > Wi-Fi > Hardware properties (all Wi-Fi networks).\nThe DNS field inside an individual Wi-Fi network can still show DHCP because adapter settings override it.")
	return err
}

func (h *Handler) Status(ctx context.Context) error {
	if h.status == nil {
		return fmt.Errorf("DNS status is not configured")
	}
	status, err := h.status(ctx)
	if err != nil {
		return fmt.Errorf("read current DNS (Windows %s): %w", status.WindowsVersion, err)
	}
	a := status.Adapter
	if _, err := fmt.Fprintf(h.output, "Windows: %s\nActive adapter: %s (index %d)\nAdapter GUID: %s\nEffective IPv4 DNS: %s\n", status.WindowsVersion, a.InterfaceName, a.InterfaceIndex, a.InterfaceGUID, strings.Join(a.Servers, ", ")); err != nil {
		return err
	}
	if status.SettingsError != "" {
		if _, err := fmt.Fprintln(h.output, "Cannot read saved DNS/DoH:", status.SettingsError); err != nil {
			return err
		}
	} else {
		mode := a.NameServer
		if a.Automatic {
			mode = "Automatic (DHCP or network profile)"
		}
		if _, err := fmt.Fprintln(h.output, "Saved adapter IPv4 DNS:", mode); err != nil {
			return err
		}
		for _, p := range a.DoH {
			if _, err := fmt.Fprintf(h.output, "DoH for saved server #%d: %s (flags=%#x)\n", p.Index+1, p.Template, p.Flags); err != nil {
				return err
			}
		}
	}
	if status.DoHError != "" {
		if _, err := fmt.Fprintln(h.output, "DoH availability:", status.DoHError); err != nil {
			return err
		}
	}
	if err := h.dnsSettingsLocation(); err != nil {
		return err
	}
	_, err = fmt.Fprintln(h.output, "Read-only status: no settings were changed and no connectivity test was run.")
	return err
}
