package app

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"doh-finder/internal/cli"
	"doh-finder/internal/model/repository/jsonfile"
	"doh-finder/internal/network/doh"
	"doh-finder/internal/platform/console"
	"doh-finder/internal/platform/systemdns"
	"doh-finder/internal/service/browse"
	"doh-finder/internal/service/catalog"
	"doh-finder/internal/service/check"
	"doh-finder/internal/source/dnscrypt"
)

// Run is the composition root; concrete adapters are wired here.
func Run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	// A read-only child process bounds native Windows DNS query duration.
	if len(args) > 0 && args[0] == "-internal-resolve" {
		if len(args) != 3 {
			return 2
		}
		index, err := strconv.Atoi(args[1])
		if err != nil || index <= 0 {
			return 2
		}
		addresses, err := systemdns.Resolve(index, args[2])
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		if err := json.NewEncoder(stdout).Encode(addresses); err != nil {
			return 1
		}
		return 0
	}
	flags := flag.NewFlagSet("doh-finder", flag.ContinueOnError)
	flags.SetOutput(stderr)
	dataDir := defaultDataDir()
	output := flags.String("output", filepath.Join(dataDir, "configs", "servers.json"), "destination JSON catalog")
	revision := flags.String("ref", "master", "upstream master or a full commit SHA")
	timeout := flags.Duration("timeout", time.Minute, "total import timeout")
	update := flags.Bool("update", false, "update the server list once without opening the menu")
	checkOnce := flags.Bool("check", false, "check the saved server list once without opening the menu")
	browseOnce := flags.Bool("browse", false, "apply the first working server from the saved check report")
	fullCycle := flags.Bool("full-cycle", false, "update, check and apply the first working server")
	prioritiesRaw := flags.String("priorities", "no-filter,no-log,dnssec", "priority order: no-filter,no-log,dnssec")
	continueAfterLast := flags.Bool("continue", false, "continue after the last confirmed working server")
	startOver := flags.Bool("start-over", false, "start a new ordered queue")
	workers := flags.Int("workers", 20, "maximum servers checked concurrently (1-128)")
	checkTimeout := flags.Duration("check-timeout", 5*time.Second, "timeout per TCP connection and DNS query")
	report := flags.String("report", filepath.Join(dataDir, "reports", "check-results.json"), "destination check report")
	state := flags.String("state", filepath.Join(dataDir, "state", "browse.json"), "saved Auto Browse queue and DNS recovery state")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	outputPath, err := filepath.Abs(*output)
	if err != nil {
		fmt.Fprintf(stderr, "Cannot resolve output path: %v\n", err)
		return 2
	}
	modeCount := 0
	for _, enabled := range []bool{*update, *checkOnce, *browseOnce, *fullCycle} {
		if enabled {
			modeCount++
		}
	}
	if flags.NArg() != 0 || strings.TrimSpace(*output) == "" || *timeout <= 0 ||
		*checkTimeout <= 0 || *workers < 1 || *workers > 128 || modeCount > 1 ||
		(*continueAfterLast && *startOver) || ((*continueAfterLast || *startOver) && !*browseOnce && !*fullCycle) || strings.TrimSpace(*report) == "" {
		fmt.Fprintln(stderr, "invalid options: choose one mode; --continue and --start-over require --browse or --full-cycle and cannot be combined")
		return 2
	}
	priorities, err := cli.ParsePriorities(*prioritiesRaw)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	reportPath, err := filepath.Abs(*report)
	if err != nil || strings.EqualFold(reportPath, outputPath) {
		fmt.Fprintln(stderr, "report path must be valid and different from the server list")
		return 2
	}
	statePath, err := filepath.Abs(*state)
	if err != nil || strings.TrimSpace(*state) == "" || strings.EqualFold(statePath, reportPath) || strings.EqualFold(statePath, outputPath) {
		fmt.Fprintln(stderr, "state path must be valid and different from catalog and report")
		return 2
	}
	logger := slog.New(slog.NewTextHandler(stderr, nil))
	client := &http.Client{Timeout: 30 * time.Second}
	defer client.CloseIdleConnections()
	source := dnscrypt.NewClient(client, *revision)
	repository := jsonfile.NewRepository(outputPath)
	service := catalog.NewService(source, repository)
	domains := []string{"example.com", "iana.org"}
	// Network errors are returned in results and printed by the collector.
	// Suppress the library's concurrent duplicate stderr messages.
	networkLogger := slog.New(slog.NewTextHandler(io.Discard, nil))
	prober := doh.NewProber(*checkTimeout, domains, networkLogger)
	checker := check.NewService(repository, jsonfile.NewRepository(reportPath), prober, *workers, *checkTimeout, domains)
	browser := browse.NewService(jsonfile.NewRepository(reportPath), jsonfile.NewRepository(statePath), systemdns.NewSystem(15*time.Second))
	clear, restoreConsole := console.Screens(stdout)
	defer restoreConsole()
	handler := cli.NewHandler(service, checker, logger, stdout).WithScreens(browser, clear).WithPriorities(priorities)
	release, err := systemdns.LockSession()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	defer release()
	if saved, exists, loadErr := browser.Load(ctx); loadErr != nil {
		fmt.Fprintln(stderr, "load saved DNS state:", loadErr)
		return 1
	} else if exists && saved.Pending != nil {
		fmt.Fprintln(stdout, "Restoring DNS settings from an interrupted, unconfirmed trial...")
		if err := browser.Recover(ctx); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
	}
	if *continueAfterLast {
		saved, exists, err := browser.Load(ctx)
		if err != nil || !exists || saved.LastWorking == nil {
			fmt.Fprintln(stderr, "--continue requires a previously confirmed working server")
			return 2
		}
	}
	if *checkOnce {
		if err := handler.Check(ctx); err != nil {
			logger.Error("server check failed", "error", err)
			return 1
		}
		fmt.Fprintf(stdout, "Report saved to: %s\n", reportPath)
		return 0
	}
	if *browseOnce {
		if _, err := handler.BrowseOnce(ctx, priorities, *continueAfterLast, false); err != nil {
			logger.Error("auto browse failed", "error", err)
			return 1
		}
		return 0
	}
	if *fullCycle {
		if err := handler.FullCycle(ctx, *timeout, priorities, *continueAfterLast); err != nil {
			logger.Error("full cycle failed", "error", err)
			return 1
		}
		return 0
	}
	if !*update {
		if err := handler.Menu(ctx, stdin, *timeout, outputPath, reportPath); err != nil {
			logger.Error("console failed", "error", err)
			return 1
		}
		return 0
	}
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	if err := handler.Run(ctx); err != nil {
		logger.Error("catalog update failed", "error", err)
		return 1
	}
	fmt.Fprintf(stdout, "Saved to: %s\n", outputPath)
	return 0
}

// Explorer and Run as administrator may start in a different working directory.
func defaultDataDir() string {
	if _, err := os.Stat(filepath.Join("configs", "servers.json")); err == nil {
		return "."
	}
	// A fresh checkout has no generated catalog yet. Recognize the project root
	// before falling back to the executable directory (which is temporary for go run).
	if _, err := os.Stat("go.mod"); err == nil {
		if _, err := os.Stat(filepath.Join("cmd", "doh-finder", "main.go")); err == nil {
			return "."
		}
	}
	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		if strings.EqualFold(filepath.Base(dir), "bin") {
			return filepath.Dir(dir)
		}
		return dir
	}
	return "."
}
