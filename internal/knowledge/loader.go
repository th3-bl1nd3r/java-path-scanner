package knowledge

import (
	"encoding/json"
	"fmt"

	"gopkg.in/yaml.v3"
)

// Load parses all embedded knowledge base files into a KnowledgeBase.
func Load() (*KnowledgeBase, error) {
	kb := &KnowledgeBase{}

	if err := kb.loadPaths(); err != nil {
		return nil, fmt.Errorf("loading paths: %w", err)
	}
	if err := kb.loadVulns(); err != nil {
		return nil, fmt.Errorf("loading vulns: %w", err)
	}
	if err := kb.loadBypasses(); err != nil {
		return nil, fmt.Errorf("loading bypasses: %w", err)
	}
	if err := kb.loadFingerprints(); err != nil {
		return nil, fmt.Errorf("loading fingerprints: %w", err)
	}

	return kb, nil
}

func (kb *KnowledgeBase) loadPaths() error {
	return yaml.Unmarshal(PathsYAML, &kb.Paths)
}

func (kb *KnowledgeBase) loadVulns() error {
	return json.Unmarshal(VulnsJSON, &kb.Vulns)
}

func (kb *KnowledgeBase) loadBypasses() error {
	return yaml.Unmarshal(BypassesYAML, &kb.Bypasses)
}

func (kb *KnowledgeBase) loadFingerprints() error {
	return yaml.Unmarshal(FingerprintsYAML, &kb.Fingerprints)
}

// TotalPaths returns the total number of paths across all groups.
func (kb *KnowledgeBase) TotalPaths() int {
	count := 0
	for _, group := range kb.Paths {
		count += len(group.Paths)
	}
	return count
}

// TotalVulns returns the number of vulnerabilities.
func (kb *KnowledgeBase) TotalVulns() int {
	return len(kb.Vulns.Vulnerabilities)
}

// TotalTechniques returns the number of bypass techniques.
func (kb *KnowledgeBase) TotalTechniques() int {
	return len(kb.Bypasses.Techniques)
}

// GetVulnsForPath returns vulnerabilities matching a path and technology.
func (kb *KnowledgeBase) GetVulnsForPath(path, technology string) []Vulnerability {
	var matches []Vulnerability
	for _, v := range kb.Vulns.Vulnerabilities {
		if v.Technology != technology {
			continue
		}
		for _, ap := range v.AffectedPaths {
			if ap == path || ap == "/*" || matchWildcard(ap, path) {
				matches = append(matches, v)
				break
			}
		}
	}
	return matches
}

// matchWildcard checks if a path matches a simple wildcard pattern.
// Supports trailing * (e.g., "/actuator/*" matches "/actuator/env").
func matchWildcard(pattern, path string) bool {
	if len(pattern) == 0 {
		return false
	}
	if pattern[len(pattern)-1] == '*' {
		prefix := pattern[:len(pattern)-1]
		return len(path) >= len(prefix) && path[:len(prefix)] == prefix
	}
	return pattern == path
}
