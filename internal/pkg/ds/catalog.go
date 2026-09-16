package ds

// Catalog contains imported source data, not live health-check results.
type Catalog struct {
	SchemaVersion int        `json:"schemaVersion"`
	Source        SourceInfo `json:"source"`
	Resolvers     []Resolver `json:"resolvers"`
}

type SourceInfo struct {
	Repository  string `json:"repository"`
	Revision    string `json:"revision"`
	URL         string `json:"url"`
	SHA256      string `json:"sha256"`
	RetrievedAt string `json:"retrievedAt"`
}

type Resolver struct {
	Name         string     `json:"name"`
	IP           *string    `json:"ip"`
	DoHURL       string     `json:"dohUrl"`
	Stamp        string     `json:"stamp"`
	Properties   Properties `json:"properties"`
	Hashes       []string   `json:"certificateHashes"`
	BootstrapDNS []string   `json:"bootstrapDns"`
}

// Properties are claims in the source stamp, not independently verified facts.
type Properties struct {
	DNSSEC   bool `json:"dnssec"`
	NoLog    bool `json:"noLog"`
	NoFilter bool `json:"noFilter"`
}
