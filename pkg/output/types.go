package output

import (
	"github.com/th3-bl1nd3r/java-path-scanner/pkg/bypass"
	"github.com/th3-bl1nd3r/java-path-scanner/pkg/fingerprint"
)

// Finding represents a confirmed security finding.
type Finding struct {
	Target          string                 `json:"target"`
	Path            string                 `json:"path"`
	URL             string                 `json:"url"`
	Severity        string                 `json:"severity"`
	Title           string                 `json:"title"`
	Description     string                 `json:"description,omitempty"`
	Technology      string                 `json:"technology"`
	StatusCode      int                    `json:"status_code"`
	ContentLength   int                    `json:"content_length"`
	CVEs            []string               `json:"cves,omitempty"`
	BypassTechnique string                 `json:"bypass_technique,omitempty"`
	SecretsFound    []string               `json:"secrets_found,omitempty"`
	ExtractedData   map[string]interface{} `json:"extracted_data,omitempty"`
	Remediation     string                 `json:"remediation,omitempty"`
	References      []string               `json:"references,omitempty"`
}

// SeverityRank returns a numeric rank for sorting (0=critical, 4=info).
func (f *Finding) SeverityRank() int {
	switch f.Severity {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium":
		return 2
	case "low":
		return 3
	default:
		return 4
	}
}

// TargetResult holds all results for a single target.
type TargetResult struct {
	Target        string
	Fingerprint   *fingerprint.Result
	Findings      []*Finding
	BypassResults []*bypass.Result
	Errors        []string
	TotalRequests int
}

// SeverityCount returns the count of findings at a given severity.
func (tr *TargetResult) SeverityCount(severity string) int {
	count := 0
	for _, f := range tr.Findings {
		if f.Severity == severity {
			count++
		}
	}
	return count
}

// Writer is the interface for all output formats.
type Writer interface {
	// OnFinding is called for each finding as it's discovered.
	OnFinding(finding *Finding)
	// OnTargetStart is called when scanning begins for a target.
	OnTargetStart(target string)
	// OnTargetDone is called when scanning completes for a target.
	OnTargetDone(result *TargetResult)
	// Flush writes any buffered output and closes resources.
	Flush() error
}

// ScanSummary holds aggregate statistics.
type ScanSummary struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
}

// HTMLReportData is the data structure passed to the HTML template.
type HTMLReportData struct {
	Timestamp     string
	TargetsCount  int
	TotalFindings int
	Summary       ScanSummary
	Targets       []HTMLTargetData
}

// HTMLTargetData holds per-target data for the HTML report.
type HTMLTargetData struct {
	URL         string
	Fingerprint *HTMLFingerprint
	Findings    []*Finding
}

// HTMLFingerprint is a simplified fingerprint for the HTML template.
type HTMLFingerprint struct {
	Technologies []string
	WAF          string
	Server       string
}
