package runner

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/ratelimit"

	"github.com/nghia/java-path-scanner/internal/knowledge"
	"github.com/nghia/java-path-scanner/pkg/bypass"
	"github.com/nghia/java-path-scanner/pkg/fingerprint"
	"github.com/nghia/java-path-scanner/pkg/httpclient"
	"github.com/nghia/java-path-scanner/pkg/output"
	"github.com/nghia/java-path-scanner/pkg/scanner"
	"github.com/nghia/java-path-scanner/pkg/urlutil"
	"github.com/nghia/java-path-scanner/pkg/validator"
)

// Runner is the main scan orchestrator.
type Runner struct {
	options       *Options
	kb            *knowledge.KnowledgeBase
	httpClient    *httpclient.Client
	rawClient     *httpclient.RawClient
	fingerprinter *fingerprint.Engine
	bruteforcer   *scanner.Bruteforcer
	bypassEngine  *bypass.Engine
	validator     *validator.Validator
	rateLimiter   *ratelimit.Limiter
	writers       []output.Writer
	targets       []string
	ctx           context.Context
	cancel        context.CancelFunc
}

// New creates a new Runner from parsed options.
func New(options *Options) (*Runner, error) {
	// Load knowledge base
	kb, err := knowledge.Load()
	if err != nil {
		return nil, fmt.Errorf("loading knowledge base: %w", err)
	}

	// Create rate limiter
	ctx, cancel := context.WithCancel(context.Background())
	limiter := ratelimit.New(ctx, uint(options.RateLimit), time.Second)

	// Create HTTP client options
	httpOpts := httpclient.DefaultOptions()
	httpOpts.Concurrency = options.Concurrency
	httpOpts.Timeout = time.Duration(options.Timeout) * time.Second
	httpOpts.VerifySSL = !options.NoSSLVerify
	httpOpts.FollowRedirects = options.FollowRedirects
	httpOpts.Proxy = options.Proxy
	httpOpts.RateLimit = options.RateLimit

	// Parse custom headers
	customHeaders := make(map[string]string)
	for _, h := range options.Headers {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 {
			customHeaders[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	httpOpts.CustomHeaders = customHeaders

	// Create HTTP clients
	client, err := httpclient.NewClient(httpOpts, limiter)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("creating HTTP client: %w", err)
	}

	rawClient := httpclient.NewRawClient(httpOpts, limiter)

	// Create engines
	fp := fingerprint.NewEngine(&kb.Fingerprints)
	bf := scanner.NewBruteforcer(&kb.Paths)
	be := bypass.NewEngine(&kb.Bypasses, options.BypassLevel, 30)
	v := validator.New()

	// Create output writers
	var writers []output.Writer
	writers = append(writers, output.NewConsoleWriter(options.NoColor, options.Verbose, options.Silent))

	if options.JSON {
		jw, err := output.NewJSONLWriter(options.Output)
		if err != nil {
			cancel()
			return nil, fmt.Errorf("creating JSON writer: %w", err)
		}
		writers = append(writers, jw)
	}

	if options.Markdown != "" {
		writers = append(writers, output.NewMarkdownWriter(options.Markdown))
	}

	if options.HTML != "" {
		writers = append(writers, output.NewHTMLWriter(options.HTML))
	}

	// Load targets
	targets, err := loadTargets(options)
	if err != nil {
		cancel()
		return nil, err
	}

	return &Runner{
		options:       options,
		kb:            kb,
		httpClient:    client,
		rawClient:     rawClient,
		fingerprinter: fp,
		bruteforcer:   bf,
		bypassEngine:  be,
		validator:     v,
		rateLimiter:   limiter,
		writers:       writers,
		targets:       targets,
		ctx:           ctx,
		cancel:        cancel,
	}, nil
}

// RunEnumeration runs the full scan pipeline.
func (r *Runner) RunEnumeration() error {
	// Setup signal handling
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigCh
		gologger.Warning().Msg("Ctrl+C detected, finishing current requests...")
		r.cancel()
		<-sigCh
		gologger.Fatal().Msg("Force exit")
		os.Exit(1)
	}()

	gologger.Info().Msgf("Starting scan of %d target(s) with bypass level: %s",
		len(r.targets), r.options.BypassLevel)
	gologger.Info().Msgf("Loaded %d paths, %d vulnerabilities, %d bypass techniques",
		r.kb.TotalPaths(), r.kb.TotalVulns(), r.kb.TotalTechniques())

	var allResults []*output.TargetResult

	for _, target := range r.targets {
		if r.ctx.Err() != nil {
			gologger.Warning().Msg("Scan cancelled")
			break
		}

		target = urlutil.NormalizeBaseURL(target)
		result := r.scanTarget(target)
		allResults = append(allResults, result)
	}

	// Flush all writers
	for _, w := range r.writers {
		if err := w.Flush(); err != nil {
			gologger.Error().Msgf("Error flushing output: %s", err)
		}
	}

	// Print final summary
	totalFindings := 0
	totalCritical := 0
	totalHigh := 0
	for _, r := range allResults {
		totalFindings += len(r.Findings)
		totalCritical += r.SeverityCount("critical")
		totalHigh += r.SeverityCount("high")
	}

	gologger.Info().Msgf("Scan completed: %d target(s), %d finding(s), %d critical, %d high",
		len(allResults), totalFindings, totalCritical, totalHigh)

	// Return exit code based on findings
	if totalCritical > 0 {
		os.Exit(2)
	}
	if totalHigh > 0 {
		os.Exit(1)
	}

	return nil
}

func (r *Runner) scanTarget(target string) *output.TargetResult {
	result := &output.TargetResult{Target: target}

	// Notify writers
	for _, w := range r.writers {
		w.OnTargetStart(target)
	}

	// Phase 1: Fingerprint
	if !r.options.NoFingerprint {
		gologger.Debug().Msgf("[%s] Phase 1: Fingerprinting", target)
		fp, err := r.fingerprinter.Fingerprint(r.ctx, target, r.httpClient)
		if err != nil {
			result.Errors = append(result.Errors, "Fingerprint error: "+err.Error())
		} else {
			result.Fingerprint = fp
			techs := fp.DetectedTechs()
			if len(techs) > 0 {
				gologger.Info().Msgf("[%s] Technologies: %s", target, strings.Join(techs, ", "))
			}
			if fp.WAFDetected != "" {
				gologger.Warning().Msgf("[%s] WAF detected: %s", target, fp.WAFDetected)
			}
		}
	}

	// Determine path groups
	var pathGroups []string
	if r.options.TechFilter != "" {
		pathGroups = strings.Split(r.options.TechFilter, ",")
		for i := range pathGroups {
			pathGroups[i] = strings.TrimSpace(pathGroups[i])
		}
	} else if result.Fingerprint != nil {
		pathGroups = r.fingerprinter.GetPathGroups(result.Fingerprint)
	} else {
		pathGroups = []string{"spring_boot_actuator", "jolokia", "tomcat", "swagger_api_docs", "generic"}
	}

	// Establish 404 baseline
	r.validator.EstablishBaseline(r.ctx, target, r.httpClient)

	// Phase 2: Path discovery
	gologger.Debug().Msgf("[%s] Phase 2: Path discovery (%d groups)", target, len(pathGroups))
	entries := r.bruteforcer.GetPathsForGroups(pathGroups)
	gologger.Info().Msgf("[%s] Scanning %d paths", target, len(entries))

	progress := r.bruteforcer.ScanTarget(r.ctx, target, r.httpClient, entries, r.options.Concurrency, nil)

	gologger.Debug().Msgf("[%s] Scan complete: %d accessible, %d bypass candidates",
		target, len(progress.Accessible), len(progress.BypassCandidates))

	// Convert accessible paths to findings
	for _, pr := range progress.Accessible {
		validation := r.validator.Validate(target, pr.Response)
		if validation.IsTruePositive {
			finding := r.createFinding(pr, validation)
			result.Findings = append(result.Findings, finding)
			for _, w := range r.writers {
				w.OnFinding(finding)
			}
		}
	}

	// Phase 3: Bypass attempts
	if len(progress.BypassCandidates) > 0 {
		gologger.Debug().Msgf("[%s] Phase 3: Bypass attempts on %d paths", target, len(progress.BypassCandidates))
		for _, pr := range progress.BypassCandidates {
			if r.ctx.Err() != nil {
				break
			}
			bypassResult := r.bypassEngine.AttemptBypasses(
				r.ctx, target,
				pr.Path, pr.StatusCode, pr.ContentLength,
				pr.Response.Body,
				r.httpClient, r.rawClient,
			)
			result.BypassResults = append(result.BypassResults, bypassResult)

			for _, success := range bypassResult.SuccessfulBypasses {
				finding := r.createBypassFinding(pr, success)
				result.Findings = append(result.Findings, finding)
				for _, w := range r.writers {
					w.OnFinding(finding)
				}
			}
		}
	}

	// Phase 4: Vulnerability correlation
	gologger.Debug().Msgf("[%s] Phase 4: Vulnerability correlation", target)
	r.correlateVulns(result)

	// Phase 5: Deep checks
	if !r.options.NoDeepChecks {
		gologger.Debug().Msgf("[%s] Phase 5: Deep checks", target)
		r.runDeepChecks(target, result)
	}

	// Sort findings by severity
	sort.Slice(result.Findings, func(i, j int) bool {
		return result.Findings[i].SeverityRank() < result.Findings[j].SeverityRank()
	})

	result.TotalRequests = int(r.httpClient.RequestCount())

	// Notify writers
	for _, w := range r.writers {
		w.OnTargetDone(result)
	}

	return result
}

func (r *Runner) createFinding(pr *scanner.PathResult, vr *validator.ValidationResult) *output.Finding {
	return &output.Finding{
		Target:        pr.Target,
		Path:          pr.Path,
		URL:           pr.URL,
		Severity:      pr.Severity,
		Title:         fmt.Sprintf("Exposed %s endpoint: %s", pr.Technology, pr.Path),
		Description:   pr.Info,
		Technology:    pr.Technology,
		StatusCode:    pr.StatusCode,
		ContentLength: pr.ContentLength,
		SecretsFound:  vr.SecretsFound,
		ExtractedData: vr.ExtractedData,
	}
}

func (r *Runner) createBypassFinding(original *scanner.PathResult, bp *bypass.Attempt) *output.Finding {
	return &output.Finding{
		Target:   original.Target,
		Path:     original.Path,
		URL:      bp.URL,
		Severity: "high",
		Title:    fmt.Sprintf("Access control bypass: %s via %s", original.Path, bp.Technique),
		Description: fmt.Sprintf(
			"Originally returned %d, bypassed to %d using %s technique. Bypass path: %s",
			original.StatusCode, bp.BypassStatus, bp.Technique, bp.BypassPath,
		),
		Technology:      original.Technology,
		StatusCode:      bp.BypassStatus,
		ContentLength:   bp.BypassLength,
		BypassTechnique: bp.Technique,
	}
}

func (r *Runner) correlateVulns(result *output.TargetResult) {
	for _, finding := range result.Findings {
		vulns := r.kb.GetVulnsForPath(finding.Path, finding.Technology)
		for _, vuln := range vulns {
			if vuln.CVE != nil && *vuln.CVE != "" {
				finding.CVEs = append(finding.CVEs, *vuln.CVE)
			}
			if severityRank(vuln.Severity) < severityRank(finding.Severity) {
				finding.Severity = vuln.Severity
			}
			if vuln.Remediation != "" {
				finding.Remediation = vuln.Remediation
			}
			finding.References = append(finding.References, vuln.References...)
			finding.Description = fmt.Sprintf("%s\n\nKnown vulnerability: %s\n%s",
				finding.Description, vuln.Title, vuln.Description)
		}
	}
}

func (r *Runner) runDeepChecks(target string, result *output.TargetResult) {
	for _, finding := range result.Findings {
		pathLower := strings.ToLower(finding.Path)

		if strings.Contains(pathLower, "heapdump") {
			r.checkHeapdump(finding)
		} else if strings.HasSuffix(pathLower, "/env") || strings.HasSuffix(pathLower, "/actuator/env") {
			r.checkActuatorEnv(finding)
		} else if strings.HasSuffix(pathLower, "/mappings") || strings.HasSuffix(pathLower, "/actuator/mappings") {
			r.checkMappings(finding)
		} else if strings.Contains(pathLower, "swagger") || strings.Contains(pathLower, "api-docs") || strings.Contains(pathLower, "openapi") {
			r.checkSwagger(target, finding)
		} else if strings.Contains(pathLower, "jolokia") {
			r.checkJolokia(target, finding)
		} else if strings.Contains(pathLower, "nacos") {
			r.checkNacos(target, finding)
		} else if strings.Contains(pathLower, "druid") {
			if finding.ExtractedData == nil {
				finding.ExtractedData = make(map[string]interface{})
			}
			finding.ExtractedData["druid_note"] = "Druid monitor is accessible. Check /druid/sql.html for SQL query history and /druid/datasource.html for database connection details."
		}
	}
}

func (r *Runner) checkHeapdump(finding *output.Finding) {
	resp := r.httpClient.Get(r.ctx, finding.URL, map[string]string{"Range": "bytes=0-1023"})
	if resp.Err == nil && (resp.StatusCode == 200 || resp.StatusCode == 206) && resp.ContentLength > 100 {
		finding.Severity = "critical"
		finding.Description += "\n\nHeapdump is downloadable! Contains in-memory secrets (passwords, tokens, keys). Download with: curl -o heapdump " + finding.URL
	}
}

func (r *Runner) checkActuatorEnv(finding *output.Finding) {
	resp := r.httpClient.Get(r.ctx, finding.URL)
	if resp.Err != nil || resp.StatusCode != 200 {
		return
	}
	envData := r.validator.AnalyzeActuatorEnv(resp)
	if secrets, ok := envData["secrets"].([]map[string]string); ok && len(secrets) > 0 {
		finding.Severity = "critical"
		for _, s := range secrets {
			finding.SecretsFound = append(finding.SecretsFound, s["type"]+": "+s["key"]+"="+s["value"])
		}
		if finding.ExtractedData == nil {
			finding.ExtractedData = make(map[string]interface{})
		}
		finding.ExtractedData["env_analysis"] = envData
	}
}

func (r *Runner) checkMappings(finding *output.Finding) {
	resp := r.httpClient.Get(r.ctx, finding.URL)
	if resp.Err != nil || resp.StatusCode != 200 {
		return
	}
	endpoints := r.validator.AnalyzeMappings(resp)
	if len(endpoints) > 0 {
		if finding.ExtractedData == nil {
			finding.ExtractedData = make(map[string]interface{})
		}
		finding.ExtractedData["discovered_endpoints"] = endpoints
		finding.Description += fmt.Sprintf("\n\nDiscovered %d custom endpoints via mappings.", len(endpoints))
	}
}

func (r *Runner) checkSwagger(target string, finding *output.Finding) {
	specPaths := []string{"/v2/api-docs", "/v3/api-docs", "/openapi.json"}
	for _, specPath := range specPaths {
		resp := r.httpClient.Get(r.ctx, urlutil.BuildURL(target, specPath))
		if resp.Err != nil || resp.StatusCode != 200 {
			continue
		}
		body := strings.TrimSpace(resp.BodyString())
		if !strings.HasPrefix(body, "{") {
			continue
		}
		apiData := r.validator.AnalyzeSwagger(resp)
		endpoints, _ := apiData["endpoints"].([]map[string]interface{})
		if len(endpoints) > 0 {
			if finding.ExtractedData == nil {
				finding.ExtractedData = make(map[string]interface{})
			}
			limit := len(endpoints)
			if limit > 50 {
				limit = 50
			}
			finding.ExtractedData["api_endpoints"] = endpoints[:limit]
			finding.ExtractedData["auth_schemes"] = apiData["auth_schemes"]
			finding.Description += fmt.Sprintf("\n\nExtracted %d API endpoints from spec.", len(endpoints))
		}
		break
	}
}

func (r *Runner) checkJolokia(target string, finding *output.Finding) {
	versionURL := urlutil.BuildURL(target, "/jolokia/version")
	resp := r.httpClient.Get(r.ctx, versionURL)
	if resp.Err == nil && resp.StatusCode == 200 {
		if finding.ExtractedData == nil {
			finding.ExtractedData = make(map[string]interface{})
		}
		body := resp.BodyString()
		if len(body) > 500 {
			body = body[:500]
		}
		finding.ExtractedData["jolokia_version"] = body
		finding.Severity = "critical"
		finding.Description += "\n\nJolokia is accessible! This allows JMX operations over HTTP. Potential RCE via MBean execution."
	}
}

func (r *Runner) checkNacos(target string, finding *output.Finding) {
	// Try auth bypass
	configURL := urlutil.BuildURL(target, "/nacos/v1/cs/configs?search=blur&dataId=&group=&pageNo=1&pageSize=10")
	resp := r.httpClient.Get(r.ctx, configURL, map[string]string{"User-Agent": "Nacos-Server"})
	if resp.Err == nil && resp.StatusCode == 200 && strings.Contains(resp.BodyString(), "totalCount") {
		finding.Severity = "critical"
		finding.Description += "\n\nNacos authentication bypass confirmed (CVE-2021-29441)! Configurations accessible via User-Agent: Nacos-Server header."
		finding.CVEs = append(finding.CVEs, "CVE-2021-29441")
	}

	// Try default credentials
	loginURL := urlutil.BuildURL(target, "/nacos/v1/auth/login")
	resp = r.httpClient.Post(r.ctx, loginURL, "username=nacos&password=nacos",
		map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
	if resp.Err == nil && resp.StatusCode == 200 && strings.Contains(resp.BodyString(), "accessToken") {
		finding.Severity = "critical"
		finding.Description += "\n\nNacos default credentials confirmed: nacos/nacos"
		finding.SecretsFound = append(finding.SecretsFound, "default_credentials: nacos/nacos")
	}
}

// Close releases all resources.
func (r *Runner) Close() {
	r.cancel()
	r.httpClient.Close()
	r.rateLimiter.Stop()
}

func severityRank(severity string) int {
	switch severity {
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

func loadTargets(options *Options) ([]string, error) {
	var targets []string

	if options.Target != "" {
		targets = append(targets, options.Target)
	}

	if options.List != "" {
		f, err := os.Open(options.List)
		if err != nil {
			return nil, fmt.Errorf("opening target list: %w", err)
		}
		defer f.Close()

		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line != "" && !strings.HasPrefix(line, "#") {
				targets = append(targets, line)
			}
		}
		if err := sc.Err(); err != nil {
			return nil, fmt.Errorf("reading target list: %w", err)
		}
	}

	if len(targets) == 0 {
		return nil, fmt.Errorf("no targets specified")
	}

	return targets, nil
}
