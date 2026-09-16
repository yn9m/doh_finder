package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

func (h *Handler) Menu(ctx context.Context, input io.Reader, timeout time.Duration, outputPath, reportPath string) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	err := h.menu(ctx, readChoices(ctx, input), timeout, outputPath, reportPath)
	if errors.Is(err, io.EOF) || errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}

func (h *Handler) screen(title string) error {
	if err := h.clear(); err != nil {
		return fmt.Errorf("clear screen: %w", err)
	}
	_, err := fmt.Fprintf(h.output, "%s\n\n", title)
	return err
}

func (h *Handler) menu(ctx context.Context, choices <-chan menuInput, timeout time.Duration, outputPath, reportPath string) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := h.screen("DOH FINDER"); err != nil {
			return err
		}
		if _, err := fmt.Fprint(h.output, "1. Update Server List\n2. Check Servers\n3. Auto Browse\n4. Full Cycle\n0. Exit\n\nSelect an option: "); err != nil {
			return err
		}
		choice, err := nextChoice(ctx, choices)
		if err != nil {
			return err
		}
		switch choice {
		case "0":
			_, err := fmt.Fprintln(h.output, "Goodbye!")
			return err
		case "1":
			if err := h.screen("UPDATE SERVER LIST"); err != nil {
				return err
			}
			updateCtx, stop := context.WithTimeout(ctx, timeout)
			err := h.Run(updateCtx)
			stop()
			if err != nil {
				_, err = fmt.Fprintf(h.output, "Update failed: %v\n", err)
			} else {
				_, err = fmt.Fprintf(h.output, "Saved to: %s\n", outputPath)
			}
			if err != nil {
				return err
			}
		case "2":
			if err := h.screen("CHECK SERVERS"); err != nil {
				return err
			}
			err := h.Check(ctx)
			if err != nil {
				_, err = fmt.Fprintf(h.output, "Check failed: %v\n", err)
			} else {
				_, err = fmt.Fprintf(h.output, "Report saved to: %s\n", reportPath)
			}
			if err != nil {
				return err
			}
		case "3":
			err := h.browse(ctx, choices, false)
			if errors.Is(err, io.EOF) || ctx.Err() != nil {
				return err
			}
			if err == nil {
				continue
			}
			if _, err := fmt.Fprintf(h.output, "Auto browse failed: %v\n", err); err != nil {
				return err
			}
		case "4":
			err := h.fullCycleMenu(ctx, choices, timeout)
			if errors.Is(err, io.EOF) || ctx.Err() != nil {
				return err
			}
			if err == nil {
				continue
			}
			if _, err := fmt.Fprintf(h.output, "Full cycle failed: %v\n", err); err != nil {
				return err
			}
		default:
			if _, err := fmt.Fprintln(h.output, "Invalid option. Enter 1, 2, 3, 4 or 0."); err != nil {
				return err
			}
		}
		if err := h.pause(ctx, choices); err != nil {
			return err
		}
	}
}

func (h *Handler) pause(ctx context.Context, choices <-chan menuInput) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, err := fmt.Fprint(h.output, "\nPress Enter to return to menu..."); err != nil {
		return err
	}
	_, err := nextChoice(ctx, choices)
	return err
}

type menuInput struct {
	line string
	err  error
}

func nextChoice(ctx context.Context, choices <-chan menuInput) (string, error) {
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case value, ok := <-choices:
		if !ok {
			return "", io.EOF
		}
		if value.err != nil {
			return "", fmt.Errorf("read input: %w", value.err)
		}
		return strings.TrimSpace(value.line), nil
	}
}

// Reading stdin separately lets Ctrl+C stop the menu while it waits for Enter.
func readChoices(ctx context.Context, input io.Reader) <-chan menuInput {
	choices := make(chan menuInput)
	go func() {
		defer close(choices)
		scanner := bufio.NewScanner(input)
		for scanner.Scan() {
			select {
			case choices <- menuInput{line: scanner.Text()}:
			case <-ctx.Done():
				return
			}
		}
		if err := scanner.Err(); err != nil {
			select {
			case choices <- menuInput{err: err}:
			case <-ctx.Done():
			}
		}
	}()
	return choices
}
