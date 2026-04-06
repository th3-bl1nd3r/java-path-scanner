package fingerprint

import (
	"context"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/th3-bl1nd3r/java-path-scanner/internal/knowledge"
	"github.com/th3-bl1nd3r/java-path-scanner/pkg/httpclient"
	"github.com/th3-bl1nd3r/java-path-scanner/pkg/urlutil"
)

var confidenceMap = map[string]float64{
	"high":   0.9,
	"medium": 0.6,
	"low":    0.3,
}

// Result holds the fingerprinting result for a target.
type Result struct {
	Target       string
	Technologies map[string]float64
	WAFDetected  string
	ServerHeader string
	Details      []string
	mu           sync.Mutex
}

// DetectedTechs returns technologies with confidence >= 0.5.
func (r *Result) DetectedTechs() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var techs []string
	for t, c := range r.Technologies {
		if c >= 0.5 {
			techs = append(techs, t)
		}
	}
	sort.Strings(techs)
	return techs
}

// AddTech adds or updates a technology detection (thread-safe).
func (r *Result) AddTech(tech string, confidence float64, detail string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	current := r.Technologies[tech]
	if confidence > current {
		r.Technologies[tech] = confidence
	}
	if confidence > 1.0 {
		r.Technologies[tech] = 1.0
	}
	if detail != "" {
		r.Details = append(r.Details, detail)
	}
}

// Engine runs technology fingerprinting.
type Engine struct {
	rules *knowledge.FingerprintsDB
}

// NewEngine creates a new fingerprint engine.
func NewEngine(rules *knowledge.FingerprintsDB) *Engine {
	return &Engine{rules: rules}
}

// Fingerprint runs full detection against a target.
func (e *Engine) Fingerprint(ctx context.Context, target string, client *httpclient.Client) (*Result, error) {
	result := &Result{
		Target:       target,
		Technologies: make(map[string]float64),
	}

	// Phase 1: Analyze root page
	rootResp := client.Get(ctx, urlutil.BuildURL(target, "/"))
	if rootResp.Err != nil {
		result.Details = append(result.Details, "Root request failed: "+rootResp.Err.Error())
		return result, nil
	}

	e.analyzeHeaders(rootResp, result)
	e.analyzeCookies(rootResp, result)
	e.analyzeBody(rootResp, result)
	e.detectWAF(rootResp, result)

	// Phase 2: Trigger error page
	errorResp := client.Get(ctx, urlutil.BuildURL(target, "/___nonexistent_path_scanner_404___"))
	if errorResp.Err == nil {
		e.analyzeErrorPage(errorResp, result)
	}

	// Phase 3: Probe known indicator paths
	e.probePaths(ctx, target, client, result)

	return result, nil
}

// GetPathGroups returns path groups to scan based on fingerprint results.
func (e *Engine) GetPathGroups(result *Result) []string {
	techToPaths := e.rules.TechToPaths
	groupSet := make(map[string]bool)

	for _, tech := range result.DetectedTechs() {
		for _, group := range techToPaths[tech] {
			groupSet[group] = true
		}
	}

	// Always include generic
	groupSet["generic"] = true

	// Fallback if nothing detected
	if len(result.DetectedTechs()) == 0 {
		for _, g := range []string{"spring_boot_actuator", "jolokia", "tomcat", "swagger_api_docs"} {
			groupSet[g] = true
		}
	}

	groups := make([]string, 0, len(groupSet))
	for g := range groupSet {
		groups = append(groups, g)
	}
	sort.Strings(groups)
	return groups
}

func (e *Engine) analyzeHeaders(resp *httpclient.Response, result *Result) {
	// Server header
	server := resp.HeaderGet("Server")
	if server != "" {
		result.ServerHeader = server
		for _, rule := range e.rules.Headers["server"] {
			if matchPattern(rule.Pattern, server) {
				if !rule.Exclude {
					conf := confidenceMap[rule.Confidence]
					result.AddTech(rule.Technology, conf, "Server header: "+server)
				}
			}
		}
	}

	// Check all header-based rules
	headerKeys := []string{"x-powered-by", "x-application-context", "x-b3-traceid",
		"x-jenkins", "x-hudson", "x-instance-identity", "liferay-portal"}
	for _, hk := range headerKeys {
		val := resp.HeaderGet(hk)
		if val == "" {
			continue
		}
		for _, rule := range e.rules.Headers[hk] {
			if matchPattern(rule.Pattern, val) {
				if rule.Exclude {
					continue
				}
				conf := confidenceMap[rule.Confidence]
				result.AddTech(rule.Technology, conf, "Header "+hk+": "+val)
			}
		}
	}
}

func (e *Engine) analyzeCookies(resp *httpclient.Response, result *Result) {
	cookieHeader := resp.HeaderGet("Set-Cookie")
	if cookieHeader == "" {
		return
	}
	cookieLower := strings.ToLower(cookieHeader)
	for _, rule := range e.rules.Cookies {
		if strings.Contains(cookieLower, strings.ToLower(rule.Name)) {
			conf := confidenceMap[rule.Confidence]
			result.AddTech(rule.Technology, conf, "Cookie: "+rule.Name)
		}
	}
}

func (e *Engine) analyzeBody(resp *httpclient.Response, result *Result) {
	body := resp.BodyString()
	if body == "" {
		return
	}
	for _, rule := range e.rules.HTMLPatterns {
		if matchPattern(rule.Pattern, body) {
			conf := confidenceMap[rule.Confidence]
			result.AddTech(rule.Technology, conf, "HTML pattern: "+truncate(rule.Pattern, 50))
		}
	}
}

func (e *Engine) analyzeErrorPage(resp *httpclient.Response, result *Result) {
	body := resp.BodyString()
	if body == "" {
		return
	}
	for _, rule := range e.rules.ErrorPages {
		if matchPattern(rule.Pattern, body) {
			conf := confidenceMap[rule.Confidence]
			result.AddTech(rule.Technology, conf, "Error page match: "+truncate(rule.Pattern, 50))
		}
	}
}

func (e *Engine) detectWAF(resp *httpclient.Response, result *Result) {
	body := resp.BodyString()
	server := resp.HeaderGet("Server")
	cookieHdr := resp.HeaderGet("Set-Cookie")

	for _, sig := range e.rules.WAFSignatures {
		detected := false

		// Check headers
		for _, h := range sig.Headers {
			if resp.HeaderGet(h) != "" {
				detected = true
				break
			}
		}

		// Check server pattern
		if !detected && sig.ServerPattern != "" && matchPattern(sig.ServerPattern, server) {
			detected = true
		}

		// Check body pattern
		if !detected && sig.BodyPattern != "" && matchPattern(sig.BodyPattern, body) {
			detected = true
		}

		// Check cookie pattern
		if !detected && sig.CookiePattern != "" && matchPattern(sig.CookiePattern, cookieHdr) {
			detected = true
		}

		if detected {
			result.WAFDetected = sig.Name
			result.Details = append(result.Details, "WAF detected: "+sig.Name)
			break
		}
	}
}

func (e *Engine) probePaths(ctx context.Context, target string, client *httpclient.Client, result *Result) {
	var wg sync.WaitGroup
	commonTechs := map[string]bool{
		"spring_boot_actuator": true,
		"tomcat":               true,
		"elasticsearch":        true,
	}

	for tech, probes := range e.rules.ProbePaths {
		if _, exists := result.Technologies[tech]; !exists && !commonTechs[tech] {
			continue
		}
		// Limit to 2 probes per tech
		limit := 2
		if len(probes) < limit {
			limit = len(probes)
		}
		for i := 0; i < limit; i++ {
			probe := probes[i]
			wg.Add(1)
			go func(tech string, probe knowledge.ProbePathRule) {
				defer wg.Done()
				e.checkProbe(ctx, target, client, tech, probe, result)
			}(tech, probe)
		}
	}
	wg.Wait()
}

func (e *Engine) checkProbe(ctx context.Context, target string, client *httpclient.Client, tech string, probe knowledge.ProbePathRule, result *Result) {
	probeURL := urlutil.BuildURL(target, probe.Path)
	resp := client.Get(ctx, probeURL)
	if resp.Err != nil {
		return
	}

	statusMatch := false
	for _, s := range probe.ExpectedStatus {
		if resp.StatusCode == s {
			statusMatch = true
			break
		}
	}

	contentMatch := probe.ExpectedContent == "" ||
		strings.Contains(strings.ToLower(resp.BodyString()), strings.ToLower(probe.ExpectedContent))

	if statusMatch && contentMatch {
		boost := confidenceMap[probe.ConfidenceBoost]
		if boost == 0 {
			boost = 0.6
		}
		result.AddTech(tech, boost, "Probe confirmed: "+probe.Path)
	}
}

func matchPattern(pattern, text string) bool {
	re, err := regexp.Compile("(?i)" + pattern)
	if err != nil {
		return strings.Contains(strings.ToLower(text), strings.ToLower(pattern))
	}
	return re.MatchString(text)
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
