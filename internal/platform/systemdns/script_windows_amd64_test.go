package systemdns

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"doh-finder/internal/pkg/ds"
)

func TestPowerShellExceptionsArePlainText(t *testing.T) {
	_, err := readSnapshotScript(context.Background(), activeInterfaceScript+"\nthrow 'Ошибка NRPT: проверка остановлена'")
	if err == nil || !strings.Contains(err.Error(), "Ошибка NRPT: проверка остановлена") {
		t.Fatalf("exception message missing or encoding broken: %v", err)
	}
	for _, unwanted := range []string{"CLIXML", "<Objs", "_x000D_", "CategoryInfo", "FullyQualifiedErrorId"} {
		if strings.Contains(err.Error(), unwanted) {
			t.Fatalf("PowerShell internals leaked to UI: %v", err)
		}
	}
}

func TestInspectReadsNRPTWithoutBlanketRejection(t *testing.T) {
	// Run the actual embedded scripts with read-only inventory cmdlets mocked.
	script := activeInterfaceScript + `
function Get-ActiveDNSAdapter { [PSCustomObject]@{ ifIndex=7; InterfaceGuid='wifi-guid'; Name='Wi-Fi' } }
function Get-DnsClientServerAddress { param($AddressFamily,$InterfaceIndex)
    if ($AddressFamily -eq 'IPv4') { [PSCustomObject]@{ ServerAddresses=@('192.0.2.1') } }
}
function Get-ItemProperty { param($Path,$ErrorAction) }
function Get-DnsClientNrptPolicy { param([switch]$Effective)
    [PSCustomObject]@{ Namespace='.corp.example'; NameServers=@('192.0.2.53'); DirectAccessEnabled=$false; DirectAccessDnsServers=$null; DnsSecValidationRequired=$true }
}
` + inspectScript
	snapshot, err := readSnapshotScript(context.Background(), script)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.NRPT) != 1 || snapshot.NRPT[0].Namespace != ".corp.example" || len(snapshot.NRPT[0].NameServers) != 1 || snapshot.NRPT[0].NameServers[0] != "192.0.2.53" || !snapshot.NRPT[0].DNSSECValidationRequired {
		t.Fatalf("policy not preserved: %+v", snapshot.NRPT)
	}
	if err := checkNRPT(snapshot.NRPT, verificationDomains); err != nil {
		t.Fatalf("unrelated policy prevented browsing: %v", err)
	}
}

func TestNRPTChangeStopsBeforeApplyingAndVerifyingCandidate(t *testing.T) {
	snapshot := ds.DNSSnapshot{InterfaceIndex: 7, InterfaceGUID: "wifi-guid", InterfaceName: "Wi-Fi"}
	s := NewSystem(time.Second)
	s.active = func(context.Context) (ds.DNSSnapshot, error) {
		current := snapshot
		current.NRPT = []ds.NRPTPolicy{{Namespace: ".", NameServers: []string{"192.0.2.53"}}}
		return current, nil
	}
	candidate := ds.ServerResult{IP: "192.0.2.1", DoHURL: "https://dns.example/dns-query"}
	for _, err := range []error{s.Apply(context.Background(), snapshot, candidate, nil), s.Verify(context.Background(), snapshot, candidate)} {
		if !errors.Is(err, ds.ErrDNSPolicyConflict) {
			t.Fatalf("policy change was not caught before native operations: %v", err)
		}
	}
}
