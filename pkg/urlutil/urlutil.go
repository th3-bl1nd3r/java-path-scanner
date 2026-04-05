package urlutil

import (
	"fmt"
	"net/url"
	"strings"
)

// NormalizeBaseURL ensures a base URL has scheme and no trailing slash.
func NormalizeBaseURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if !strings.HasPrefix(raw, "http://") && !strings.HasPrefix(raw, "https://") {
		raw = "https://" + raw
	}
	raw = strings.TrimRight(raw, "/")
	return raw
}

// BuildURL creates a URL by joining base and path, letting net/url normalize.
func BuildURL(base, path string) string {
	base = NormalizeBaseURL(base)
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return base + path
}

// BuildRawURL creates a URL preserving encoded characters in the path.
// This is critical for bypass payloads containing %2f, %252e, etc.
func BuildRawURL(base, rawPath string) string {
	base = NormalizeBaseURL(base)
	if !strings.HasPrefix(rawPath, "/") {
		rawPath = "/" + rawPath
	}
	return base + rawPath
}

// ApplyContextPrefix generates path variants with a context prefix.
// e.g., prefix="/app", path="/actuator/env" -> ["/app/actuator/env", "/actuator/env"]
func ApplyContextPrefix(path string, prefixes []string) []string {
	results := []string{path}
	for _, prefix := range prefixes {
		prefix = strings.TrimRight(prefix, "/")
		if prefix == "" {
			continue
		}
		results = append(results, prefix+path)
	}
	return results
}

// ParseTarget extracts scheme, host, port from a target URL.
func ParseTarget(raw string) (scheme, host string, port int, err error) {
	raw = NormalizeBaseURL(raw)
	u, err := url.Parse(raw)
	if err != nil {
		return "", "", 0, fmt.Errorf("invalid URL: %w", err)
	}
	scheme = u.Scheme
	host = u.Hostname()
	portStr := u.Port()
	if portStr != "" {
		_, err = fmt.Sscanf(portStr, "%d", &port)
		if err != nil {
			return "", "", 0, fmt.Errorf("invalid port: %w", err)
		}
	} else if scheme == "https" {
		port = 443
	} else {
		port = 80
	}
	return
}
