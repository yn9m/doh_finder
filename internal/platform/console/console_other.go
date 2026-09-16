//go:build !windows

package console

import (
	"fmt"
	"io"
	"os"
)

func Screens(output io.Writer) (func() error, func()) {
	clear := func() error { return nil }
	if file, ok := output.(*os.File); ok {
		if info, err := file.Stat(); err == nil && info.Mode()&os.ModeCharDevice != 0 {
			clear = func() error { _, err := fmt.Fprint(output, "\x1b[2J\x1b[3J\x1b[H"); return err }
		}
	}
	return clear, func() {}
}
