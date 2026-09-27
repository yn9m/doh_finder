package systemdns

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"doh-finder/internal/pkg/ds"
)

func TestActiveAdapterSelection(t *testing.T) {
	// Execute the actual embedded selector with inventory cmdlets replaced by
	// deterministic fixtures; no host adapter or DNS settings are changed.
	for _, tc := range []struct {
		name, interfaces, routes, adapters string
		wantIndex                          int
		wantErr                            bool
	}{
		{"Ethernet preferred", `[14,25,"Connected"],[7,50,"Connected"]`, `[14,0],[7,0]`, `[14,"Up"],[7,"Up"]`, 14, false},
		{"Wi-Fi preferred by total metric", `[14,5,"Connected"],[7,50,"Connected"]`, `[14,100],[7,0]`, `[14,"Up"],[7,"Up"]`, 7, false},
		{"Wi-Fi after Ethernet disconnect", `[14,5,"Disconnected"],[7,50,"Connected"]`, `[14,0],[7,0]`, `[14,"Up"],[7,"Up"]`, 7, false},
		{"down adapter ignored", `[14,5,"Connected"],[7,50,"Connected"]`, `[14,0],[7,0]`, `[14,"Down"],[7,"Up"]`, 7, false},
		{"virtual adapter lower preference", `[14,25,"Connected"],[9,35,"Connected"]`, `[14,0],[9,9999]`, `[14,"Up"],[9,"Up"]`, 14, false},
		{"multiple routes for same adapter", `[14,25,"Connected"]`, `[14,0],[14,0]`, `[14,"Up"]`, 14, false},
		{"ambiguous default routes", `[14,25,"Connected"],[7,25,"Connected"]`, `[14,0],[7,0]`, `[14,"Up"],[7,"Up"]`, 0, true},
		{"disconnected", `[14,25,"Disconnected"]`, `[14,0]`, `[14,"Down"]`, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mocks := fmt.Sprintf(`
$testInterfaces = '[%s]' | ConvertFrom-Json
$testRoutes = '[%s]' | ConvertFrom-Json
$testAdapters = '[%s]' | ConvertFrom-Json
function Get-NetIPInterface { param($AddressFamily)
    foreach ($row in $testInterfaces) { [PSCustomObject]@{ InterfaceIndex=$row[0]; InterfaceMetric=$row[1]; ConnectionState=$row[2] } }
}
function Get-NetRoute { param($AddressFamily,$DestinationPrefix,$PolicyStore)
    foreach ($row in $testRoutes) { [PSCustomObject]@{ InterfaceIndex=$row[0]; RouteMetric=$row[1]; State='Alive' } }
}
function Get-NetAdapter { param([switch]$IncludeHidden)
    foreach ($row in $testAdapters) { [PSCustomObject]@{ ifIndex=$row[0]; Status=$row[1]; Name="adapter-$($row[0])"; InterfaceGuid="guid-$($row[0])" } }
}
`, tc.interfaces, tc.routes, tc.adapters)
			script := mocks + activeInterfaceScript + `
$a = Get-ActiveDNSAdapter
[PSCustomObject]@{interfaceIndex=[int]$a.ifIndex;interfaceGuid=$a.InterfaceGuid;interfaceName=$a.Name} | ConvertTo-Json -Compress
`
			got, err := readSnapshotScript(context.Background(), script)
			if (err != nil) != tc.wantErr {
				t.Fatalf("snapshot=%+v error=%v", got, err)
			}
			if err == nil && got.InterfaceIndex != tc.wantIndex {
				t.Fatalf("selected %d, want %d", got.InterfaceIndex, tc.wantIndex)
			}
		})
	}
}

func TestRouteChangePreventsNativeApplyAndVerify(t *testing.T) {
	snapshot := ds.DNSSnapshot{InterfaceIndex: 14, InterfaceGUID: "old-guid", InterfaceName: "Ethernet"}
	for _, tc := range []struct {
		name    string
		current ds.DNSSnapshot
		err     error
	}{
		{"Wi-Fi takeover", ds.DNSSnapshot{InterfaceIndex: 7, InterfaceGUID: "new-guid", InterfaceName: "Wi-Fi"}, nil},
		{"reused interface index", ds.DNSSnapshot{InterfaceIndex: 14, InterfaceGUID: "new-guid"}, nil},
		{"connection lost", ds.DNSSnapshot{}, errors.New("no route")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := NewSystem(time.Second)
			s.active = func(context.Context) (ds.DNSSnapshot, error) { return tc.current, tc.err }
			candidate := ds.ServerResult{IP: "192.0.2.1", DoHURL: "https://dns.example/dns-query"}
			for _, err := range []error{s.Apply(context.Background(), snapshot, candidate, nil), s.Verify(context.Background(), snapshot, candidate)} {
				if !errors.Is(err, ds.ErrActiveInterfaceChanged) {
					t.Fatalf("native operation was not stopped at route guard: %v", err)
				}
			}
		})
	}
}
