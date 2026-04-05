package output

import (
	"fmt"
	"strings"

	"github.com/logrusorgru/aurora/v4"
	"github.com/projectdiscovery/gologger"
)

// ConsoleWriter outputs findings in ProjectDiscovery style.
type ConsoleWriter struct {
	au      *aurora.Aurora
	verbose bool
	silent  bool
}

// NewConsoleWriter creates a new console output writer.
func NewConsoleWriter(noColor, verbose, silent bool) *ConsoleWriter {
	return &ConsoleWriter{
		au:      aurora.New(aurora.WithColors(!noColor)),
		verbose: verbose,
		silent:  silent,
	}
}

// OnFinding prints a finding in PD style: [severity] [tech] url [status] [details]
func (cw *ConsoleWriter) OnFinding(f *Finding) {
	sevTag := cw.colorSeverity(f.Severity)
	techTag := cw.au.Cyan("[" + f.Technology + "]").String()

	if f.BypassTechnique != "" {
		techTag = cw.au.Green("[bypass:" + f.BypassTechnique + "]").String()
	}

	statusTag := fmt.Sprintf("[%d]", f.StatusCode)
	sizeTag := fmt.Sprintf("[%d bytes]", f.ContentLength)

	var parts []string
	parts = append(parts, sevTag, techTag, f.URL, statusTag, sizeTag)

	if len(f.CVEs) > 0 {
		parts = append(parts, cw.au.Yellow("["+strings.Join(f.CVEs, ",")+"]").String())
	}

	if len(f.SecretsFound) > 0 {
		parts = append(parts, cw.au.Red("[secrets:"+fmt.Sprintf("%d", len(f.SecretsFound))+"]").String())
	}

	// Use gologger.Silent for results (shown even in silent mode)
	gologger.Silent().Msgf("%s", strings.Join(parts, " "))
}

// OnTargetStart logs target scan start.
func (cw *ConsoleWriter) OnTargetStart(target string) {
	if !cw.silent {
		gologger.Info().Msgf("Scanning target: %s", target)
	}
}

// OnTargetDone logs target scan completion.
func (cw *ConsoleWriter) OnTargetDone(result *TargetResult) {
	if cw.silent {
		return
	}

	critical := result.SeverityCount("critical")
	high := result.SeverityCount("high")
	medium := result.SeverityCount("medium")
	low := result.SeverityCount("low")

	gologger.Info().Msgf("Target %s: %d findings (%d critical, %d high, %d medium, %d low)",
		result.Target, len(result.Findings), critical, high, medium, low)

	if result.Fingerprint != nil {
		techs := result.Fingerprint.DetectedTechs()
		if len(techs) > 0 {
			gologger.Info().Msgf("Technologies: %s", strings.Join(techs, ", "))
		}
		if result.Fingerprint.WAFDetected != "" {
			gologger.Warning().Msgf("WAF detected: %s", result.Fingerprint.WAFDetected)
		}
	}

	if cw.verbose {
		for _, err := range result.Errors {
			gologger.Error().Msgf("Error: %s", err)
		}
	}
}

// Flush is a no-op for console output.
func (cw *ConsoleWriter) Flush() error {
	return nil
}

func (cw *ConsoleWriter) colorSeverity(severity string) string {
	tag := "[" + severity + "]"
	switch severity {
	case "critical":
		return cw.au.BgRed(tag).Bold().String()
	case "high":
		return cw.au.Red(tag).Bold().String()
	case "medium":
		return cw.au.Yellow(tag).String()
	case "low":
		return cw.au.Green(tag).String()
	case "info":
		return cw.au.Blue(tag).String()
	default:
		return tag
	}
}
