package main

//go:generate go run github.com/akavel/rsrc@v0.10.2 -manifest app.manifest -arch amd64 -o rsrc_windows_amd64.syso

import (
	"context"
	"os"
	"os/signal"

	"doh-finder/internal/app"
)

func main() {
	os.Exit(run())
}

func run() int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	return app.Run(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr)
}
