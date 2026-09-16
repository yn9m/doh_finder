package systemdns

import (
	"fmt"
	"net"
	"runtime"
	"strings"
	"unsafe"

	"doh-finder/internal/pkg/ds"
	"golang.org/x/sys/windows"
)

var iphelper = windows.NewLazySystemDLL("iphlpapi.dll")
var getSettings = iphelper.NewProc("GetInterfaceDnsSettings")
var setSettings = iphelper.NewProc("SetInterfaceDnsSettings")
var freeSettings = iphelper.NewProc("FreeInterfaceDnsSettings")
var dnsAPI = windows.NewLazySystemDLL("dnsapi.dll")
var queryEx = dnsAPI.NewProc("DnsQueryEx")
var flushCache = dnsAPI.NewProc("DnsFlushResolverCache")

type globalSettings struct {
	Version                      uint32
	Flags                        uint64
	Hostname, Domain, SearchList *uint16
	SettingFlags                 uint64
}

func checkDoHAllowed() error {
	proc := iphelper.NewProc("GetDnsSettings")
	if err := proc.Find(); err != nil {
		return err
	}
	settings := globalSettings{Version: 2}
	code, _, _ := proc.Call(uintptr(unsafe.Pointer(&settings)))
	if code != 0 {
		return fmt.Errorf("GetDnsSettings: %w", windows.Errno(code))
	}
	defer iphelper.NewProc("FreeDnsSettings").Call(uintptr(unsafe.Pointer(&settings)))
	if settings.SettingFlags&1 == 0 || settings.SettingFlags&(0x8|0x200) != 0 {
		return fmt.Errorf("Windows global settings or policy disable DoH (flags=%#x)", settings.SettingFlags)
	}
	return nil
}

// Native structures follow the Windows x64 ABI (netioapi.h).
type interfaceSettings struct {
	Version                                                                 uint32
	Flags                                                                   uint64
	Domain, NameServer, SearchList                                          *uint16
	RegistrationEnabled, RegisterAdapterName, EnableLLMNR, QueryAdapterName uint32
	ProfileNameServer                                                       *uint16
	DisableUnconstrainedQueries                                             uint32
	SupplementalSearchList                                                  *uint16
	Count                                                                   uint32
	Properties                                                              *serverProperty
	ProfileCount                                                            uint32
	ProfileProperties                                                       *serverProperty
}
type serverProperty struct {
	Version, Index, Type uint32
	Settings             *dohSettings
}
type dohSettings struct {
	Template *uint16
	Flags    uint64
}

func nativeRead(guid string) (string, []ds.DoHSetting, error) {
	id, err := windows.GUIDFromString(guid)
	if err != nil {
		return "", nil, err
	}
	if err := getSettings.Find(); err != nil {
		return "", nil, fmt.Errorf("Windows native DoH settings are unavailable: %w", err)
	}
	settings := interfaceSettings{Version: 3}
	code, _, _ := getSettings.Call(uintptr(unsafe.Pointer(&id)), uintptr(unsafe.Pointer(&settings)))
	if code != 0 {
		return "", nil, fmt.Errorf("GetInterfaceDnsSettings: %w", windows.Errno(code))
	}
	defer freeSettings.Call(uintptr(unsafe.Pointer(&settings)))
	if windows.UTF16PtrToString(settings.ProfileNameServer) != "" || settings.ProfileCount != 0 {
		return "", nil, fmt.Errorf("profile-specific DNS settings are not supported")
	}
	if settings.Count > 64 {
		return "", nil, fmt.Errorf("too many native DNS properties")
	}
	props := make([]ds.DoHSetting, 0, settings.Count)
	for _, p := range unsafe.Slice(settings.Properties, settings.Count) {
		if p.Version != 1 || p.Type != 1 || p.Settings == nil {
			return "", nil, fmt.Errorf("unsupported native DNS property")
		}
		props = append(props, ds.DoHSetting{Index: p.Index, Template: windows.UTF16PtrToString(p.Settings.Template), Flags: p.Settings.Flags})
	}
	return windows.UTF16PtrToString(settings.NameServer), props, nil
}

func nativeWrite(guid, servers string, props []ds.DoHSetting) error {
	id, err := windows.GUIDFromString(guid)
	if err != nil {
		return err
	}
	if err := setSettings.Find(); err != nil {
		return err
	}
	names, err := windows.UTF16PtrFromString(servers)
	if err != nil {
		return err
	}
	settings := interfaceSettings{Version: 3, Flags: 0x0002 | 0x1000, NameServer: names}
	if strings.TrimSpace(servers) == "" {
		// Clearing the static list restores DHCP. DOH requires a nonempty list.
		settings.Flags = 0x0002
	}
	doh := make([]dohSettings, len(props))
	native := make([]serverProperty, len(props))
	for i, p := range props {
		// AUTO properties obtain their template from the system list. Get may
		// return the expanded template, but Set requires NULL for AUTO.
		if p.Template != "" && p.Flags&1 == 0 {
			doh[i].Template, err = windows.UTF16PtrFromString(p.Template)
			if err != nil {
				return err
			}
		}
		doh[i].Flags = p.Flags
		native[i] = serverProperty{Version: 1, Index: p.Index, Type: 1, Settings: &doh[i]}
	}
	if len(native) > 0 {
		settings.Count = uint32(len(native))
		settings.Properties = &native[0]
	}
	code, _, _ := setSettings.Call(uintptr(unsafe.Pointer(&id)), uintptr(unsafe.Pointer(&settings)))
	runtime.KeepAlive(native)
	runtime.KeepAlive(doh)
	runtime.KeepAlive(names)
	if code != 0 {
		return fmt.Errorf("SetInterfaceDnsSettings: %w", windows.Errno(code))
	}
	flushCache.Call()
	return nil
}

type queryRequest struct {
	Version           uint32
	Name              *uint16
	Type              uint16
	Options           uint64
	Servers           unsafe.Pointer
	InterfaceIndex    uint32
	Callback, Context uintptr
}
type queryResult struct {
	Version, Status uint32
	Options         uint64
	Records         *windows.DNSRecord
	Reserved        uintptr
}

// Resolve uses the selected Windows adapter, bypassing caches, hosts and LLMNR.
// It runs in a short-lived child process so the parent can enforce a timeout.
func Resolve(index int, host string) ([]string, error) {
	name, err := windows.UTF16PtrFromString(host)
	if err != nil {
		return nil, err
	}
	request := queryRequest{Version: 1, Name: name, Type: windows.DNS_TYPE_A,
		Options: 0x8 | 0x20 | 0x40 | 0x80 | 0x800 | 0x1000, InterfaceIndex: uint32(index)}
	result := queryResult{Version: 1}
	code, _, _ := queryEx.Call(uintptr(unsafe.Pointer(&request)), uintptr(unsafe.Pointer(&result)), 0)
	runtime.KeepAlive(name)
	if result.Records != nil {
		defer windows.DnsRecordListFree(result.Records, 1)
	}
	if code != 0 {
		return nil, fmt.Errorf("Windows DNS query for %s: %w", host, windows.Errno(code))
	}
	addresses := []string{}
	for r := result.Records; r != nil; r = r.Next {
		if r.Type != windows.DNS_TYPE_A || r.Length < 4 {
			continue
		}
		bytes := (*[4]byte)(unsafe.Pointer(&r.Data[0]))
		ip := net.IPv4(bytes[0], bytes[1], bytes[2], bytes[3])
		if ip.IsUnspecified() || ip.IsLoopback() {
			continue
		}
		addresses = append(addresses, ip.String())
	}
	if len(addresses) == 0 {
		return nil, fmt.Errorf("Windows DNS returned no usable A records for %s", host)
	}
	return addresses, nil
}

func sameServers(a, b string) bool {
	split := func(v string) string {
		return strings.Join(strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ' ' || r == ';' }), ",")
	}
	return split(a) == split(b)
}
