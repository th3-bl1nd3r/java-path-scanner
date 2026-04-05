package knowledge

import (
	"testing"
)

func TestLoadKnowledgeBase(t *testing.T) {
	kb, err := Load()
	if err != nil {
		t.Fatalf("failed to load knowledge base: %v", err)
	}

	t.Run("paths_loaded", func(t *testing.T) {
		total := kb.TotalPaths()
		if total < 200 {
			t.Errorf("expected at least 200 paths, got %d", total)
		}
		t.Logf("loaded %d paths across %d groups", total, len(kb.Paths))
	})

	t.Run("paths_have_required_fields", func(t *testing.T) {
		for groupName, group := range kb.Paths {
			if group.Description == "" {
				t.Errorf("group %s has empty description", groupName)
			}
			for i, p := range group.Paths {
				if p.Path == "" {
					t.Errorf("group %s path[%d] has empty path", groupName, i)
				}
				if p.Severity == "" {
					t.Errorf("group %s path[%d] (%s) has empty severity", groupName, i, p.Path)
				}
			}
		}
	})

	t.Run("vulns_loaded", func(t *testing.T) {
		total := kb.TotalVulns()
		if total < 30 {
			t.Errorf("expected at least 30 vulnerabilities, got %d", total)
		}
		t.Logf("loaded %d vulnerabilities", total)
	})

	t.Run("vulns_have_required_fields", func(t *testing.T) {
		for _, v := range kb.Vulns.Vulnerabilities {
			if v.ID == "" {
				t.Error("vulnerability has empty ID")
			}
			if v.Title == "" {
				t.Errorf("vulnerability %s has empty title", v.ID)
			}
			if v.Severity == "" {
				t.Errorf("vulnerability %s has empty severity", v.ID)
			}
		}
	})

	t.Run("default_credentials_loaded", func(t *testing.T) {
		if len(kb.Vulns.DefaultCredentials) == 0 {
			t.Error("no default credentials loaded")
		}
		if _, ok := kb.Vulns.DefaultCredentials["tomcat_manager"]; !ok {
			t.Error("missing tomcat_manager default credentials")
		}
	})

	t.Run("bypasses_loaded", func(t *testing.T) {
		total := kb.TotalTechniques()
		if total < 10 {
			t.Errorf("expected at least 10 bypass techniques, got %d", total)
		}
		t.Logf("loaded %d bypass techniques", total)
	})

	t.Run("bypass_levels_defined", func(t *testing.T) {
		for _, level := range []string{"passive", "moderate", "aggressive"} {
			if _, ok := kb.Bypasses.BypassLevels[level]; !ok {
				t.Errorf("missing bypass level: %s", level)
			}
		}
	})

	t.Run("fingerprints_loaded", func(t *testing.T) {
		if len(kb.Fingerprints.Headers) == 0 {
			t.Error("no header fingerprint rules loaded")
		}
		if len(kb.Fingerprints.Cookies) == 0 {
			t.Error("no cookie fingerprint rules loaded")
		}
		if len(kb.Fingerprints.WAFSignatures) == 0 {
			t.Error("no WAF signatures loaded")
		}
		if len(kb.Fingerprints.TechToPaths) == 0 {
			t.Error("no tech-to-paths mapping loaded")
		}
	})

	t.Run("vuln_path_matching", func(t *testing.T) {
		matches := kb.GetVulnsForPath("/actuator/gateway/routes", "spring_cloud")
		if len(matches) == 0 {
			t.Error("expected vuln match for /actuator/gateway/routes")
		}
	})
}
