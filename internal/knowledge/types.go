package knowledge

// PathEntry represents a single scannable path.
type PathEntry struct {
	Path     string `yaml:"path" json:"path"`
	Info     string `yaml:"info" json:"info"`
	Severity string `yaml:"severity" json:"severity"`
}

// PathGroup represents a technology group of paths.
type PathGroup struct {
	Description     string      `yaml:"description"`
	Paths           []PathEntry `yaml:"paths"`
	ContextPrefixes []string    `yaml:"context_prefixes,omitempty"`
}

// PathsDB maps technology name to its path group.
type PathsDB map[string]PathGroup

// Vulnerability represents a single CVE/vulnerability entry.
type Vulnerability struct {
	ID          string        `json:"id"`
	CVE         *string       `json:"cve"`
	Technology  string        `json:"technology"`
	AffectedPaths []string    `json:"affected_paths"`
	Title       string        `json:"title"`
	Severity    string        `json:"severity"`
	CVSS        float64       `json:"cvss"`
	Description string        `json:"description"`
	Exploitation string       `json:"exploitation"`
	Remediation string        `json:"remediation"`
	References  []string      `json:"references"`
	Detection   DetectionRule `json:"detection"`
}

// DetectionRule defines how to detect a vulnerability.
type DetectionRule struct {
	Path              string            `json:"path,omitempty"`
	Method            string            `json:"method,omitempty"`
	Headers           map[string]string `json:"headers,omitempty"`
	SuccessIndicators []string          `json:"success_indicators,omitempty"`
	Note              string            `json:"note,omitempty"`
}

// Credential represents a default username/password pair.
type Credential struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// VulnsDB is the top-level vulnerability database.
type VulnsDB struct {
	Vulnerabilities    []Vulnerability            `json:"vulnerabilities"`
	DefaultCredentials map[string][]Credential    `json:"default_credentials"`
}

// BypassTechnique defines a single bypass technique.
type BypassTechnique struct {
	Name                 string                `yaml:"name"`
	Description          string                `yaml:"description"`
	Risk                 string                `yaml:"risk"`
	Patterns             []string              `yaml:"patterns,omitempty"`
	RequestModifications []RequestModification `yaml:"request_modifications,omitempty"`
	EffectiveAgainst     []string              `yaml:"effective_against,omitempty"`
	Notes                string                `yaml:"notes,omitempty"`
}

// RequestModification defines a header-based bypass modification.
type RequestModification struct {
	Headers     map[string]string `yaml:"headers"`
	Description string            `yaml:"description"`
}

// BypassLevel defines which techniques are available at a given level.
type BypassLevel struct {
	Description string   `yaml:"description"`
	Techniques  []string `yaml:"techniques"`
}

// BypassChainStep is one step in a multi-step bypass chain.
type BypassChainStep struct {
	Technique   string            `yaml:"technique"`
	Pattern     string            `yaml:"pattern,omitempty"`
	Headers     map[string]string `yaml:"headers,omitempty"`
	Explanation string            `yaml:"explanation"`
}

// BypassChain is a curated multi-step bypass sequence.
type BypassChain struct {
	Description string            `yaml:"description"`
	Steps       []BypassChainStep `yaml:"steps"`
}

// BypassesDB is the top-level bypass technique database.
type BypassesDB struct {
	BypassLevels map[string]BypassLevel     `yaml:"bypass_levels"`
	Techniques   map[string]BypassTechnique `yaml:"techniques"`
	BypassChains map[string]BypassChain     `yaml:"bypass_chains"`
}

// FingerprintRule is a pattern-based technology detection rule.
type FingerprintRule struct {
	Pattern    string `yaml:"pattern"`
	Name       string `yaml:"name,omitempty"`
	Technology string `yaml:"technology"`
	Confidence string `yaml:"confidence"`
	Exclude    bool   `yaml:"exclude,omitempty"`
	Notes      string `yaml:"notes,omitempty"`
}

// ProbePathRule defines a path to probe for technology confirmation.
type ProbePathRule struct {
	Path            string `yaml:"path"`
	ExpectedStatus  []int  `yaml:"expected_status"`
	ExpectedContent string `yaml:"expected_content"`
	ConfidenceBoost string `yaml:"confidence_boost"`
}

// WAFSignature identifies a WAF/CDN product.
type WAFSignature struct {
	Name          string   `yaml:"name"`
	Headers       []string `yaml:"headers,omitempty"`
	ServerPattern string   `yaml:"server_pattern,omitempty"`
	BodyPattern   string   `yaml:"body_pattern,omitempty"`
	CookiePattern string   `yaml:"cookie_pattern,omitempty"`
	Notes         string   `yaml:"notes,omitempty"`
}

// FingerprintsDB is the top-level fingerprinting database.
type FingerprintsDB struct {
	Headers       map[string][]FingerprintRule `yaml:"headers"`
	Cookies       []FingerprintRule            `yaml:"cookies"`
	ErrorPages    []FingerprintRule            `yaml:"error_pages"`
	HTMLPatterns  []FingerprintRule            `yaml:"html_patterns"`
	ProbePaths    map[string][]ProbePathRule   `yaml:"probe_paths"`
	TechToPaths   map[string][]string          `yaml:"tech_to_paths"`
	WAFSignatures []WAFSignature               `yaml:"waf_signatures"`
}

// KnowledgeBase holds all loaded knowledge data.
type KnowledgeBase struct {
	Paths        PathsDB
	Vulns        VulnsDB
	Bypasses     BypassesDB
	Fingerprints FingerprintsDB
}
