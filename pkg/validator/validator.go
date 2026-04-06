package validator

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/th3-bl1nd3r/java-path-scanner/pkg/httpclient"
	"github.com/th3-bl1nd3r/java-path-scanner/pkg/urlutil"
)

// SecretPattern defines a regex pattern and its type.
type SecretPattern struct {
	Pattern *regexp.Regexp
	Type    string
}

var falsePositivePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)<title>404`),
	regexp.MustCompile(`(?i)page not found`),
	regexp.MustCompile(`(?i)not found</`),
	regexp.MustCompile(`(?i)the page you requested`),
	regexp.MustCompile(`(?i)requested URL was not found`),
	regexp.MustCompile(`(?i)does not exist`),
	regexp.MustCompile(`(?i)cannot be found`),
	regexp.MustCompile(`(?i)no such page`),
}

var wafBlockPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)access denied`),
	regexp.MustCompile(`(?i)request blocked`),
	regexp.MustCompile(`(?i)security policy`),
	regexp.MustCompile(`(?i)web application firewall`),
	regexp.MustCompile(`(?i)forbidden by`),
	regexp.MustCompile(`(?i)your request has been blocked`),
	regexp.MustCompile(`(?i)automated requests`),
	regexp.MustCompile(`(?i)bot detected`),
	regexp.MustCompile(`(?i)captcha`),
	regexp.MustCompile(`(?i)challenge-platform`),
}

var secretPatterns = []SecretPattern{
	{regexp.MustCompile(`(?i)password\s*[=:]\s*['"]?([^'"\s,}{]+)`), "password"},
	{regexp.MustCompile(`(?i)passwd\s*[=:]\s*['"]?([^'"\s,}{]+)`), "password"},
	{regexp.MustCompile(`(?i)secret\s*[=:]\s*['"]?([^'"\s,}{]+)`), "secret"},
	{regexp.MustCompile(`(?i)api[_-]?key\s*[=:]\s*['"]?([^'"\s,}{]+)`), "api_key"},
	{regexp.MustCompile(`(?i)access[_-]?token\s*[=:]\s*['"]?([^'"\s,}{]+)`), "access_token"},
	{regexp.MustCompile(`(?i)auth[_-]?token\s*[=:]\s*['"]?([^'"\s,}{]+)`), "auth_token"},
	{regexp.MustCompile(`(?i)private[_-]?key\s*[=:]\s*['"]?([^'"\s,}{]+)`), "private_key"},
	{regexp.MustCompile(`(?i)aws_access_key_id\s*[=:]\s*['"]?([A-Z0-9]{20})`), "aws_access_key"},
	{regexp.MustCompile(`(?i)aws_secret_access_key\s*[=:]\s*['"]?([A-Za-z0-9/+=]{40})`), "aws_secret_key"},
	{regexp.MustCompile(`jdbc:[a-z]+://[^\s'"]+`), "jdbc_url"},
	{regexp.MustCompile(`mongodb://[^\s'"]+`), "mongodb_url"},
	{regexp.MustCompile(`redis://[^\s'"]+`), "redis_url"},
	{regexp.MustCompile(`amqp://[^\s'"]+`), "amqp_url"},
}

var maskedPatterns = []string{"****", "xxxx", "<masked>", "******", "hidden"}
var maskedAllStars = regexp.MustCompile(`^\*+$`)

// ValidationResult classifies a response.
type ValidationResult struct {
	IsTruePositive bool
	Confidence     float64
	Classification string // "true_positive", "false_positive", "waf_block", "bypass_candidate", "info_leak", "interesting", "error", "unknown"
	Details        string
	SecretsFound   []string
	ExtractedData  map[string]interface{}
}

// Validator filters false positives and analyzes responses.
type Validator struct {
	similarityThreshold float64
	minContentLength    int
	baseline404         map[string]*httpclient.Response
}

// New creates a new response validator.
func New() *Validator {
	return &Validator{
		similarityThreshold: 0.85,
		minContentLength:    50,
		baseline404:         make(map[string]*httpclient.Response),
	}
}

// EstablishBaseline sends requests to nonexistent paths to establish a soft-404 baseline.
func (v *Validator) EstablishBaseline(ctx context.Context, target string, client *httpclient.Client) {
	for i := 0; i < 3; i++ {
		randomPath := fmt.Sprintf("/___fp_baseline_%d_%d___", i, 99999)
		resp := client.Get(ctx, urlutil.BuildURL(target, randomPath))
		if resp.Err == nil {
			v.baseline404[target] = resp
			return
		}
	}
}

// Validate classifies a response to determine if it's a true positive.
func (v *Validator) Validate(target string, response *httpclient.Response) *ValidationResult {
	if response.Err != nil {
		return &ValidationResult{
			IsTruePositive: false,
			Confidence:     1.0,
			Classification: "error",
			Details:        "Request error: " + response.Err.Error(),
		}
	}

	// Check for WAF block
	if v.isWAFBlock(response) {
		return &ValidationResult{
			IsTruePositive: false,
			Confidence:     0.8,
			Classification: "waf_block",
			Details:        "Response appears to be a WAF block page",
		}
	}

	// Check for soft 404
	if v.isSoft404(target, response) {
		return &ValidationResult{
			IsTruePositive: false,
			Confidence:     0.85,
			Classification: "false_positive",
			Details:        "Response matches 404 baseline (soft 404)",
		}
	}

	// Check for known false positive patterns
	if v.hasFalsePositivePatterns(response) {
		return &ValidationResult{
			IsTruePositive: false,
			Confidence:     0.7,
			Classification: "false_positive",
			Details:        "Response body matches false positive pattern",
		}
	}

	// Too small to be meaningful
	if response.ContentLength < v.minContentLength && response.StatusCode == 200 {
		return &ValidationResult{
			IsTruePositive: false,
			Confidence:     0.5,
			Classification: "false_positive",
			Details:        fmt.Sprintf("Response too small (%d bytes)", response.ContentLength),
		}
	}

	// 200 with substantial content = likely true positive
	if response.StatusCode == 200 && response.ContentLength >= v.minContentLength {
		secrets := v.CheckSecrets(response)
		return &ValidationResult{
			IsTruePositive: true,
			Confidence:     0.9,
			Classification: "true_positive",
			Details:        "Accessible endpoint with content",
			SecretsFound:   secrets,
		}
	}

	// 500 errors may leak information
	if response.StatusCode >= 500 {
		infoLeak := v.checkInfoLeak(response)
		hasLeak := len(infoLeak) > 0
		conf := 0.3
		class := "interesting"
		if hasLeak {
			conf = 0.6
			class = "info_leak"
		}
		result := &ValidationResult{
			IsTruePositive: hasLeak,
			Confidence:     conf,
			Classification: class,
			Details:        fmt.Sprintf("Server error with %s", class),
		}
		if hasLeak {
			result.ExtractedData = map[string]interface{}{"info_leak": infoLeak}
		}
		return result
	}

	// 403/401 = bypass candidate
	if response.StatusCode == 401 || response.StatusCode == 403 {
		return &ValidationResult{
			IsTruePositive: false,
			Confidence:     0.5,
			Classification: "bypass_candidate",
			Details:        fmt.Sprintf("Access denied (%d) - bypass candidate", response.StatusCode),
		}
	}

	// 405 = endpoint exists
	if response.StatusCode == 405 {
		return &ValidationResult{
			IsTruePositive: true,
			Confidence:     0.7,
			Classification: "true_positive",
			Details:        "Endpoint exists (405 Method Not Allowed)",
		}
	}

	// Redirects
	if response.StatusCode >= 300 && response.StatusCode < 400 {
		location := response.HeaderGet("Location")
		return &ValidationResult{
			IsTruePositive: true,
			Confidence:     0.6,
			Classification: "interesting",
			Details:        "Redirect to " + location,
		}
	}

	return &ValidationResult{
		IsTruePositive: false,
		Confidence:     0.3,
		Classification: "unknown",
		Details:        fmt.Sprintf("Unclassified response: %d", response.StatusCode),
	}
}

func (v *Validator) isSoft404(target string, response *httpclient.Response) bool {
	baseline := v.baseline404[target]
	if baseline == nil {
		return false
	}
	if response.StatusCode != baseline.StatusCode {
		return false
	}
	sim := contentSimilarity(baseline.Body, response.Body)
	return sim >= v.similarityThreshold
}

func (v *Validator) isWAFBlock(response *httpclient.Response) bool {
	body := strings.ToLower(response.BodyString())
	for _, p := range wafBlockPatterns {
		if p.MatchString(body) {
			return true
		}
	}
	return false
}

func (v *Validator) hasFalsePositivePatterns(response *httpclient.Response) bool {
	body := strings.ToLower(response.BodyString())
	matches := 0
	for _, p := range falsePositivePatterns {
		if p.MatchString(body) {
			matches++
		}
	}
	return matches >= 2
}

// CheckSecrets scans response body for potential secrets.
func (v *Validator) CheckSecrets(response *httpclient.Response) []string {
	body := response.BodyString()
	var secrets []string

	for _, sp := range secretPatterns {
		matches := sp.Pattern.FindAllStringSubmatch(body, -1)
		for _, m := range matches {
			val := m[0]
			if len(m) > 1 {
				val = m[1]
			}
			if val != "" && !isMasked(val) {
				display := val
				if len(display) > 50 {
					display = display[:50] + "..."
				}
				secrets = append(secrets, sp.Type+": "+display)
			}
		}
	}

	return secrets
}

func (v *Validator) checkInfoLeak(response *httpclient.Response) map[string]string {
	body := response.BodyString()
	leaks := make(map[string]string)

	// Stack traces
	if regexp.MustCompile(`at\s+[\w.]+\([\w]+\.java:\d+\)`).MatchString(body) {
		leaks["stack_trace"] = "Java stack trace detected"
	}

	// Internal paths
	re := regexp.MustCompile(`(/[\w/]+/(?:WEB-INF|META-INF|classes|lib)/[\w/.]+)`)
	if matches := re.FindAllString(body, 5); len(matches) > 0 {
		leaks["internal_paths"] = strings.Join(matches, ", ")
	}

	// Class names
	re2 := regexp.MustCompile(`((?:com|org|net|io)\.[\w.]{10,})`)
	if matches := re2.FindAllString(body, 5); len(matches) > 0 {
		leaks["class_names"] = strings.Join(unique(matches), ", ")
	}

	// Version info
	re3 := regexp.MustCompile(`(?i)(?:version|v)\s*[=:]\s*['"]?([\d.]+)`)
	if matches := re3.FindAllStringSubmatch(body, 3); len(matches) > 0 {
		var versions []string
		for _, m := range matches {
			if len(m) > 1 {
				versions = append(versions, m[1])
			}
		}
		if len(versions) > 0 {
			leaks["versions"] = strings.Join(unique(versions), ", ")
		}
	}

	// SQL errors
	if regexp.MustCompile(`(?i)(?:SQL|ORA-|mysql|postgresql|sqlite)`).MatchString(body) {
		leaks["sql_error"] = "Database error pattern detected"
	}

	return leaks
}

func isMasked(value string) bool {
	lower := strings.ToLower(strings.Trim(value, "'\""))
	for _, p := range maskedPatterns {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return maskedAllStars.MatchString(lower)
}

func contentSimilarity(a, b []byte) float64 {
	if len(a) == 0 && len(b) == 0 {
		return 1.0
	}
	if len(a) == 0 || len(b) == 0 {
		return 0.0
	}

	maxLen := 5000
	if len(a) > maxLen {
		a = a[:maxLen]
	}
	if len(b) > maxLen {
		b = b[:maxLen]
	}

	linesA := strings.Split(string(a), "\n")
	linesB := strings.Split(string(b), "\n")

	setA := make(map[string]bool)
	for _, l := range linesA {
		l = strings.TrimSpace(l)
		if l != "" {
			setA[l] = true
		}
	}
	setB := make(map[string]bool)
	for _, l := range linesB {
		l = strings.TrimSpace(l)
		if l != "" {
			setB[l] = true
		}
	}

	if len(setA) == 0 && len(setB) == 0 {
		return 1.0
	}

	intersection := 0
	for l := range setA {
		if setB[l] {
			intersection++
		}
	}
	union := len(setA) + len(setB) - intersection
	if union == 0 {
		return 1.0
	}
	return float64(intersection) / float64(union)
}

func unique(ss []string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, s := range ss {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	return result
}
