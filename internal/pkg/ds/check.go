package ds

type ProbeResult struct {
	Status    string `json:"status"`
	ElapsedMS int64  `json:"elapsedMs"`
	Error     string `json:"error,omitempty"`
}

type DNSResult struct {
	ProbeResult
	Domain     string   `json:"domain"`
	Addresses  []string `json:"addresses"`
	TLSVersion string   `json:"tlsVersion,omitempty"`
	Protocol   string   `json:"protocol,omitempty"`
}

type ServerResult struct {
	Name       string      `json:"name"`
	IP         string      `json:"ip"`
	DoHURL     string      `json:"dohUrl"`
	Properties Properties  `json:"properties"`
	TCP        ProbeResult `json:"tcp"`
	DNS        []DNSResult `json:"dns"`
	Success    bool        `json:"success"`
}

type CheckReport struct {
	StartedAt  string     `json:"startedAt"`
	FinishedAt string     `json:"finishedAt"`
	Source     SourceInfo `json:"source"`
	Workers    int        `json:"workers"`
	TimeoutMS  int64      `json:"timeoutMs"`
	Domains    []string   `json:"domains"`
	Checked    int        `json:"checked"`
	Failed     int        `json:"failed"`
	// Results contains only servers that passed all checks, in catalog order.
	Results []ServerResult `json:"results"`
}

type CheckProgress struct {
	Completed int
	Total     int
	Result    ServerResult
}
