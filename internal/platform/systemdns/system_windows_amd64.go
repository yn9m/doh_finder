package systemdns

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf16"

	"doh-finder/internal/pkg/ds"
	"golang.org/x/sys/windows"
)

//go:embed inspect.ps1
var inspectScript string

type System struct{ timeout time.Duration }

func NewSystem(timeout time.Duration) *System { return &System{timeout: timeout} }

func LockSession() (func(), error) {
	name, _ := windows.UTF16PtrFromString(`Global\doh-finder-auto-browse`)
	handle, err := windows.CreateMutex(nil, false, name)
	if err != nil && !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		return nil, err
	}
	if errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		windows.CloseHandle(handle)
		return nil, fmt.Errorf("another doh-finder menu is already open; close it before starting another instance")
	}
	return func() { windows.CloseHandle(handle) }, nil
}

func inspect(ctx context.Context) (ds.DNSSnapshot, error) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	var encoded bytes.Buffer
	for _, v := range utf16.Encode([]rune(inspectScript)) {
		_ = binary.Write(&encoded, binary.LittleEndian, v)
	}
	shell := os.Getenv("SystemRoot") + `\System32\WindowsPowerShell\v1.0\powershell.exe`
	cmd := exec.CommandContext(ctx, shell, "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", base64.StdEncoding.EncodeToString(encoded.Bytes()))
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	body, err := cmd.Output()
	if err != nil {
		return ds.DNSSnapshot{}, fmt.Errorf("inspect IPv4 adapter: %w: %s", err, stderr.String())
	}
	var snapshot ds.DNSSnapshot
	if err := json.Unmarshal(bytes.TrimPrefix(body, []byte{0xef, 0xbb, 0xbf}), &snapshot); err != nil {
		return snapshot, err
	}
	return snapshot, nil
}

func (s *System) Snapshot(ctx context.Context, _ []ds.ServerResult) (ds.DNSSnapshot, error) {
	if !windows.GetCurrentProcessToken().IsElevated() {
		return ds.DNSSnapshot{}, fmt.Errorf("option 3 changes Windows DNS: restart doh-finder.exe using Run as administrator")
	}
	if err := checkDoHAllowed(); err != nil {
		return ds.DNSSnapshot{}, err
	}
	snapshot, err := inspect(ctx)
	if err != nil {
		return snapshot, err
	}
	snapshot.NameServer, snapshot.DoH, err = nativeRead(snapshot.InterfaceGUID)
	snapshot.Automatic = strings.TrimSpace(snapshot.NameServer) == ""
	return snapshot, err
}

func desired(primary ds.ServerResult, backup *ds.ServerResult) (string, []ds.DoHSetting) {
	names := primary.IP
	props := []ds.DoHSetting{{Index: 0, Template: primary.DoHURL, Flags: 2}}
	if backup != nil && backup.IP != primary.IP {
		names += "," + backup.IP
		props = append(props, ds.DoHSetting{Index: 1, Template: backup.DoHURL, Flags: 2})
	}
	return names, props
}

func (s *System) Apply(ctx context.Context, snapshot ds.DNSSnapshot, primary ds.ServerResult, backup *ds.ServerResult) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	names, props := desired(primary, backup)
	if err := nativeWrite(snapshot.InterfaceGUID, names, props); err != nil {
		return err
	}
	return verifySettings(snapshot.InterfaceGUID, names, props)
}

func verifySettings(guid, names string, props []ds.DoHSetting) error {
	actual, settings, err := nativeRead(guid)
	if err != nil {
		return err
	}
	if !sameServers(actual, names) || !reflect.DeepEqual(settings, props) {
		return fmt.Errorf("Windows DNS/DoH readback differs from requested configuration")
	}
	return nil
}

func (s *System) Restore(ctx context.Context, snapshot ds.DNSSnapshot) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := nativeWrite(snapshot.InterfaceGUID, snapshot.NameServer, snapshot.DoH); err != nil {
		return err
	}
	return verifySettings(snapshot.InterfaceGUID, snapshot.NameServer, snapshot.DoH)
}

func (s *System) resolve(ctx context.Context, index int, domain string) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	exe, err := os.Executable()
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, exe, "-internal-resolve", strconv.Itoa(index), domain)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	body, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("system DNS %s: %w: %s", domain, err, stderr.String())
	}
	var addresses []string
	if err := json.Unmarshal(body, &addresses); err != nil {
		return nil, err
	}
	return addresses, nil
}

func (s *System) Verify(ctx context.Context, snapshot ds.DNSSnapshot, primary ds.ServerResult) error {
	if err := checkDoHAllowed(); err != nil {
		return err
	}
	names, props := desired(primary, nil)
	if err := verifySettings(snapshot.InterfaceGUID, names, props); err != nil {
		return err
	}
	for _, domain := range []string{"example.com", "www.iana.org"} {
		addresses, err := s.resolve(ctx, snapshot.InterfaceIndex, domain)
		if err != nil {
			return err
		}
		if err := checkSite(ctx, domain, addresses, s.timeout); err != nil {
			return err
		}
	}
	return verifySettings(snapshot.InterfaceGUID, names, props)
}
