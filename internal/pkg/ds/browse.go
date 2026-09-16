package ds

// BrowseState keeps a snapshot of the queue so new checks cannot reorder a session.
type BrowseState struct {
	SchemaVersion int            `json:"schemaVersion"`
	Priorities    []int          `json:"priorities"`
	Queue         []ServerResult `json:"queue"`
	Current       int            `json:"current"`
	UpdatedAt     string         `json:"updatedAt"`
	LastWorking   *ServerResult  `json:"lastWorking,omitempty"`
	Backup        *ServerResult  `json:"backup,omitempty"`
	Pending       *DNSSnapshot   `json:"pendingRestore,omitempty"`
	Verified      bool           `json:"verified"`
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
