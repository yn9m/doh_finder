package cli

import (
	"context"
	"fmt"
	"io"
	"log/slog"
)

type Handler struct {
	service           CatalogService
	checker           CheckService
	logger            *slog.Logger
	output            io.Writer
	browser           BrowseService
	clear             func() error
	defaultPriorities []int
}

func NewHandler(service CatalogService, checker CheckService, logger *slog.Logger, output io.Writer) *Handler {
	return &Handler{service: service, checker: checker, logger: logger, output: output, clear: func() error { return nil }, defaultPriorities: []int{1, 2, 3}}
}

func (h *Handler) WithPriorities(order []int) *Handler {
	h.defaultPriorities = append([]int(nil), order...)
	return h
}

func (h *Handler) WithScreens(browser BrowseService, clear func() error) *Handler {
	h.browser = browser
	if clear != nil {
		h.clear = clear
	}
	return h
}

func (h *Handler) Run(ctx context.Context) error {
	h.logger.Debug("updating DoH catalog")
	if _, err := fmt.Fprintln(h.output, "Updating server list..."); err != nil {
		return fmt.Errorf("write progress: %w", err)
	}
	catalog, err := h.service.Update(ctx)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(h.output,
		"Server list updated: %d IPv4 DoH servers.\n",
		len(catalog.Resolvers))
	if err != nil {
		return fmt.Errorf("write import summary: %w", err)
	}
	return nil
}
