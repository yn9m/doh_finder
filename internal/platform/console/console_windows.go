package console

import (
	"fmt"
	"io"
	"os"

	"golang.org/x/sys/windows"
)

func Screens(output io.Writer) (func() error, func()) {
	noop := func() error { return nil }
	file, ok := output.(*os.File)
	if !ok {
		return noop, func() {}
	}
	handle := windows.Handle(file.Fd())
	var mode uint32
	if windows.GetConsoleMode(handle, &mode) != nil {
		return noop, func() {}
	}
	if windows.SetConsoleMode(handle, mode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING) != nil {
		return noop, func() {}
	}
	return func() error { _, err := fmt.Fprint(output, "\x1b[2J\x1b[3J\x1b[H"); return err }, func() { _ = windows.SetConsoleMode(handle, mode) }
}
