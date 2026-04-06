package output

import (
	"html/template"
	"os"
	"time"

	"github.com/th3-bl1nd3r/java-path-scanner/internal/knowledge"
)

// HTMLWriter generates a standalone HTML report.
type HTMLWriter struct {
	path    string
	results []*TargetResult
}

// NewHTMLWriter creates a new HTML writer.
func NewHTMLWriter(path string) *HTMLWriter {
	return &HTMLWriter{path: path}
}

// OnFinding is a no-op (HTML is batched).
func (hw *HTMLWriter) OnFinding(_ *Finding) {}

// OnTargetStart is a no-op.
func (hw *HTMLWriter) OnTargetStart(_ string) {}

// OnTargetDone collects results for the final report.
func (hw *HTMLWriter) OnTargetDone(result *TargetResult) {
	hw.results = append(hw.results, result)
}

// Flush renders and writes the complete HTML report.
func (hw *HTMLWriter) Flush() error {
	if len(hw.results) == 0 {
		return nil
	}

	funcMap := template.FuncMap{
		"add": func(a, b int) int { return a + b },
		"truncate": func(s string, maxLen int) string {
			if len(s) <= maxLen {
				return s
			}
			return s[:maxLen] + "..."
		},
		"first": func(items []string, n int) []string {
			if len(items) <= n {
				return items
			}
			return items[:n]
		},
	}

	tmpl, err := template.New("report.html").Funcs(funcMap).Parse(knowledge.ReportHTMLTemplate)
	if err != nil {
		return err
	}

	data := hw.buildReportData()

	f, err := os.Create(hw.path)
	if err != nil {
		return err
	}
	defer f.Close()

	return tmpl.Execute(f, data)
}

func (hw *HTMLWriter) buildReportData() HTMLReportData {
	data := HTMLReportData{
		Timestamp:    time.Now().Format("2006-01-02 15:04:05"),
		TargetsCount: len(hw.results),
	}

	for _, r := range hw.results {
		data.TotalFindings += len(r.Findings)

		td := HTMLTargetData{
			URL:      r.Target,
			Findings: r.Findings,
		}

		if r.Fingerprint != nil {
			td.Fingerprint = &HTMLFingerprint{
				Technologies: r.Fingerprint.DetectedTechs(),
				WAF:          r.Fingerprint.WAFDetected,
				Server:       r.Fingerprint.ServerHeader,
			}
		}

		for _, f := range r.Findings {
			switch f.Severity {
			case "critical":
				data.Summary.Critical++
			case "high":
				data.Summary.High++
			case "medium":
				data.Summary.Medium++
			case "low":
				data.Summary.Low++
			default:
				data.Summary.Info++
			}
		}

		data.Targets = append(data.Targets, td)
	}

	return data
}
