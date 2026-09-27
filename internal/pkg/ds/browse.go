package ds

import "errors"

// A changed route invalidates the entire trial, rather than just one DNS server.
var ErrActiveInterfaceChanged = errors.New("active IPv4 interface changed or is unavailable")

var ErrDNSSettingsOverridden = errors.New("Windows is not using the requested IPv4 DNS settings")

// BrowseState keeps a snapshot of the queue so new checks cannot reorder a session.
type BrowseState struct {
	SchemaVersion    int            `json:"schemaVersion"`
	Priorities       []int          `json:"priorities"`
	Queue            []ServerResult `json:"queue"`
	Current          int            `json:"current"`
	UpdatedAt        string         `json:"updatedAt"`
	LastWorking      *ServerResult  `json:"lastWorking,omitempty"`
	Backup           *ServerResult  `json:"backup,omitempty"`
	ConfirmedThrough *ServerResult  `json:"confirmedThrough,omitempty"`
	TrialPrimary     *ServerResult  `json:"trialPrimary,omitempty"`
	TrialBackup      *ServerResult  `json:"trialBackup,omitempty"`
	InterfaceName    string         `json:"interfaceName,omitempty"`
	Pending          *DNSSnapshot   `json:"pendingRestore,omitempty"`
	Verified         bool           `json:"verified"`
}

type DoHSetting struct {
	Index    uint32 `json:"index"`
	Template string `json:"template"`
	Flags    uint64 `json:"flags"`
}

type DNSSnapshot struct {
	InterfaceIndex int          `json:"interfaceIndex"`
	InterfaceGUID  string       `json:"interfaceGuid"`
	InterfaceName  string       `json:"interfaceName"`
	Automatic      bool         `json:"automatic"`
	NameServer     string       `json:"nameServer"`
	Servers        []string     `json:"servers"`
	DoH            []DoHSetting `json:"doh"`
}

type DNSStatus struct {
	Adapter        DNSSnapshot
	WindowsVersion string
	SettingsError  string
	DoHError       string
}
