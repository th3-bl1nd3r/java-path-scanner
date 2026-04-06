package bypass

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/th3-bl1nd3r/java-path-scanner/internal/knowledge"
	"github.com/th3-bl1nd3r/java-path-scanner/pkg/httpclient"
	"github.com/th3-bl1nd3r/java-path-scanner/pkg/urlutil"
)

// Engine generates and tests path normalization bypasses.
type Engine struct {
	db                   *knowledge.BypassesDB
	level                string
	successCodes         map[int]bool
	contentDiffThreshold float64
	maxAttempts          int
}

// NewEngine creates a new bypass engine.
func NewEngine(db *knowledge.BypassesDB, level string, maxAttempts int) *Engine {
	if maxAttempts <= 0 {
		maxAttempts = 30
	}
	return &Engine{
		db:    db,
		level: level,
		successCodes: map[int]bool{
			200: true, 301: true, 302: true,
		},
		contentDiffThreshold: 0.3,
		maxAttempts:          maxAttempts,
	}
}

// GenerateBypassURLs generates all bypass URL variants for a path.
// Uses round-robin interleaving across techniques so that the
// max_attempts limit captures a diverse set of bypass types.
func (e *Engine) GenerateBypassURLs(path string) []Variant {
	activeTechniques := e.getActiveTechniques()
	techniques := e.db.Techniques

	// Collect variants per technique
	var perTechnique [][]Variant

	for _, techName := range activeTechniques {
		tech, ok := techniques[techName]
		if !ok {
			continue
		}
		var techVariants []Variant

		// URL-based patterns
		for _, pattern := range tech.Patterns {
			resolved := resolvePattern(pattern, path)
			if resolved != "" && resolved != path {
				techVariants = append(techVariants, Variant{
					Path:      resolved,
					Technique: techName,
					Headers:   map[string]string{},
				})
			}
		}

		// Header-based modifications
		for _, mod := range tech.RequestModifications {
			headers := make(map[string]string)
			for k, v := range mod.Headers {
				headers[k] = strings.ReplaceAll(v, "{path}", path)
			}
			if len(headers) > 0 {
				techVariants = append(techVariants, Variant{
					Path:      path,
					Technique: techName,
					Headers:   headers,
				})
			}
		}

		if len(techVariants) > 0 {
			perTechnique = append(perTechnique, techVariants)
		}
	}

	// Round-robin interleave
	maxLen := 0
	for _, tv := range perTechnique {
		if len(tv) > maxLen {
			maxLen = len(tv)
		}
	}

	var interleaved []Variant
	for i := 0; i < maxLen; i++ {
		for _, techVariants := range perTechnique {
			if i < len(techVariants) {
				interleaved = append(interleaved, techVariants[i])
			}
		}
	}

	// Deduplicate
	seen := make(map[string]bool)
	var unique []Variant
	for _, v := range interleaved {
		key := v.Path + "|" + sortedHeaders(v.Headers)
		if !seen[key] {
			seen[key] = true
			unique = append(unique, v)
		}
	}

	if len(unique) > e.maxAttempts {
		unique = unique[:e.maxAttempts]
	}
	return unique
}

// AttemptBypasses tests all bypass techniques on a 403/401 path.
func (e *Engine) AttemptBypasses(
	ctx context.Context,
	target string,
	originalPath string,
	originalStatus int,
	originalLength int,
	originalBody []byte,
	client *httpclient.Client,
	rawClient *httpclient.RawClient,
) *Result {
	result := &Result{
		Target:         target,
		OriginalPath:   originalPath,
		OriginalStatus: originalStatus,
	}

	variants := e.GenerateBypassURLs(originalPath)
	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, variant := range variants {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		go func(v Variant) {
			defer wg.Done()
			attempt := e.tryBypass(ctx, target, v, originalStatus, originalLength, originalBody, client, rawClient)
			if attempt == nil {
				return
			}
			mu.Lock()
			result.Attempts = append(result.Attempts, attempt)
			if attempt.Success {
				result.SuccessfulBypasses = append(result.SuccessfulBypasses, attempt)
			}
			mu.Unlock()
		}(variant)
	}

	wg.Wait()
	return result
}

func (e *Engine) tryBypass(
	ctx context.Context,
	target string,
	variant Variant,
	originalStatus, originalLength int,
	originalBody []byte,
	client *httpclient.Client,
	rawClient *httpclient.RawClient,
) *Attempt {
	bypassURL := urlutil.BuildRawURL(target, variant.Path)

	var resp *httpclient.Response
	if len(variant.Headers) > 0 {
		resp = client.Get(ctx, bypassURL, variant.Headers)
	} else {
		// Use raw client to preserve encoded paths
		resp = rawClient.Get(ctx, bypassURL, nil)
	}

	if resp.Err != nil {
		return nil
	}

	similarity := contentSimilarity(originalBody, resp.Body)

	attempt := &Attempt{
		OriginalPath:      variant.Path,
		BypassPath:        variant.Path,
		Technique:         variant.Technique,
		URL:               bypassURL,
		OriginalStatus:    originalStatus,
		BypassStatus:      resp.StatusCode,
		OriginalLength:    originalLength,
		BypassLength:      resp.ContentLength,
		ContentSimilarity: similarity,
		HeadersUsed:       variant.Headers,
		Response:          resp,
	}

	// Determine success
	if e.successCodes[resp.StatusCode] && resp.StatusCode != originalStatus {
		attempt.Success = true
	} else if attempt.SignificantContentDiff() &&
		resp.StatusCode != 404 &&
		resp.ContentLength > int(float64(originalLength)*1.5) {
		attempt.Success = true
	}

	return attempt
}

func (e *Engine) getActiveTechniques() []string {
	levelConfig, ok := e.db.BypassLevels[e.level]
	if !ok {
		levelConfig = e.db.BypassLevels["passive"]
	}
	return levelConfig.Techniques
}

// resolvePattern resolves a bypass pattern template into an actual path.
func resolvePattern(pattern, path string) string {
	cleanPath := strings.TrimLeft(path, "/")
	parts := strings.SplitN(cleanPath, "/", 2)

	var base, target string
	if len(parts) == 2 {
		base = "/" + parts[0]
		target = parts[1]
	} else {
		base = ""
		target = parts[0]
	}

	result := pattern
	result = strings.ReplaceAll(result, "{path}", path)
	result = strings.ReplaceAll(result, "{base}", base)
	result = strings.ReplaceAll(result, "{target}", target)
	result = strings.ReplaceAll(result, "{PATH_UPPER}", strings.ToUpper(path))
	result = strings.ReplaceAll(result, "{Path_Title}", strings.Title(path)) //nolint:staticcheck
	result = strings.ReplaceAll(result, "{path_mixed}", mixedCase(path))

	if !strings.HasPrefix(result, "/") {
		result = "/" + result
	}

	return result
}

// mixedCase capitalizes the first letter of each path segment.
func mixedCase(s string) string {
	parts := strings.Split(s, "/")
	var mixed []string
	for _, part := range parts {
		if part == "" {
			mixed = append(mixed, part)
		} else if len(part) == 1 {
			mixed = append(mixed, strings.ToUpper(part))
		} else {
			mixed = append(mixed, strings.ToUpper(part[:1])+part[1:])
		}
	}
	return strings.Join(mixed, "/")
}

func sortedHeaders(h map[string]string) string {
	if len(h) == 0 {
		return ""
	}
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%s", k, h[k]))
	}
	return strings.Join(parts, "&")
}

// contentSimilarity computes a simple line-set Jaccard similarity.
func contentSimilarity(a, b []byte) float64 {
	if len(a) == 0 && len(b) == 0 {
		return 1.0
	}
	if len(a) == 0 || len(b) == 0 {
		return 0.0
	}

	// Truncate for comparison
	maxLen := 5000
	if len(a) > maxLen {
		a = a[:maxLen]
	}
	if len(b) > maxLen {
		b = b[:maxLen]
	}

	linesA := strings.Split(string(a), "\n")
	linesB := strings.Split(string(b), "\n")

	setA := make(map[string]bool, len(linesA))
	for _, l := range linesA {
		l = strings.TrimSpace(l)
		if l != "" {
			setA[l] = true
		}
	}

	setB := make(map[string]bool, len(linesB))
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
