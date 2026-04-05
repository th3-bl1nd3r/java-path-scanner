package bypass

import (
	"testing"

	"github.com/nghia/java-path-scanner/internal/knowledge"
)

func loadTestEngine(t *testing.T, level string, maxAttempts int) *Engine {
	t.Helper()
	kb, err := knowledge.Load()
	if err != nil {
		t.Fatalf("failed to load knowledge base: %v", err)
	}
	return NewEngine(&kb.Bypasses, level, maxAttempts)
}

func TestGenerateBypassURLs(t *testing.T) {
	engine := loadTestEngine(t, "aggressive", 30)

	t.Run("generates_variants", func(t *testing.T) {
		variants := engine.GenerateBypassURLs("/actuator/env")
		if len(variants) == 0 {
			t.Fatal("expected variants, got none")
		}
		// Should not include original unmodified path without headers
		for _, v := range variants {
			if v.Path == "/actuator/env" && len(v.Headers) == 0 {
				t.Error("should not include original path without modifications")
			}
		}
	})

	t.Run("trailing_slash_variants", func(t *testing.T) {
		variants := engine.GenerateBypassURLs("/admin")
		paths := extractPaths(variants)
		assertContains(t, paths, "/admin/")
		assertContains(t, paths, "/admin/.")
	})

	t.Run("semicolon_bypass_variants", func(t *testing.T) {
		variants := engine.GenerateBypassURLs("/actuator/env")
		paths := extractPaths(variants)
		found := false
		for _, p := range paths {
			if containsStr(p, ";") {
				found = true
				break
			}
		}
		if !found {
			t.Error("expected at least one semicolon-based variant")
		}
	})

	t.Run("url_encoding_variants", func(t *testing.T) {
		variants := engine.GenerateBypassURLs("/admin")
		paths := extractPaths(variants)
		found := false
		for _, p := range paths {
			if containsStr(p, "%2f") || containsStr(p, "%2F") {
				found = true
				break
			}
		}
		if !found {
			t.Error("expected URL-encoded variant")
		}
	})

	t.Run("double_encoding_variants", func(t *testing.T) {
		variants := engine.GenerateBypassURLs("/admin")
		paths := extractPaths(variants)
		found := false
		for _, p := range paths {
			if containsStr(p, "%252") {
				found = true
				break
			}
		}
		if !found {
			t.Error("expected double-encoded variant")
		}
	})

	t.Run("header_override_variants", func(t *testing.T) {
		variants := engine.GenerateBypassURLs("/admin")
		headerVariants := filterWithHeaders(variants)
		if len(headerVariants) == 0 {
			t.Fatal("expected header override variants")
		}
		found := false
		for _, v := range headerVariants {
			if _, ok := v.Headers["X-Original-URL"]; ok {
				found = true
				break
			}
		}
		if !found {
			t.Error("expected X-Original-URL header variant")
		}
	})

	t.Run("ip_bypass_headers", func(t *testing.T) {
		bigEngine := loadTestEngine(t, "aggressive", 100)
		variants := bigEngine.GenerateBypassURLs("/admin")
		headerVariants := filterWithHeaders(variants)
		found := false
		for _, v := range headerVariants {
			if _, ok := v.Headers["X-Forwarded-For"]; ok {
				found = true
				break
			}
		}
		if !found {
			t.Error("expected X-Forwarded-For header variant")
		}
	})

	t.Run("passive_excludes_advanced", func(t *testing.T) {
		passiveEngine := loadTestEngine(t, "passive", 30)
		variants := passiveEngine.GenerateBypassURLs("/admin")
		for _, v := range variants {
			if v.Technique == "header_override" && len(v.Headers) > 0 {
				t.Error("passive level should not include header_override")
			}
			if v.Technique == "unicode_normalization" {
				t.Error("passive level should not include unicode_normalization")
			}
		}
	})

	t.Run("deduplication", func(t *testing.T) {
		variants := engine.GenerateBypassURLs("/admin")
		seen := make(map[string]bool)
		for _, v := range variants {
			key := v.Path + "|" + sortedHeaders(v.Headers)
			if seen[key] {
				t.Errorf("duplicate variant: %s", v.Path)
			}
			seen[key] = true
		}
	})

	t.Run("max_attempts_limit", func(t *testing.T) {
		smallEngine := loadTestEngine(t, "aggressive", 5)
		variants := smallEngine.GenerateBypassURLs("/admin")
		if len(variants) > 5 {
			t.Errorf("expected max 5 variants, got %d", len(variants))
		}
	})

	t.Run("case_variation", func(t *testing.T) {
		variants := engine.GenerateBypassURLs("/actuator/env")
		paths := extractPaths(variants)
		assertContains(t, paths, "/ACTUATOR/ENV")
	})

	t.Run("path_starts_with_slash", func(t *testing.T) {
		variants := engine.GenerateBypassURLs("/admin")
		for _, v := range variants {
			if len(v.Path) > 0 && v.Path[0] != '/' {
				t.Errorf("path doesn't start with /: %s", v.Path)
			}
		}
	})
}

func TestResolvePattern(t *testing.T) {
	t.Run("simple_path", func(t *testing.T) {
		result := resolvePattern("{path}/", "/admin")
		if result != "/admin/" {
			t.Errorf("expected /admin/, got %s", result)
		}
	})

	t.Run("base_target_split", func(t *testing.T) {
		result := resolvePattern("{base}/../{target}", "/actuator/env")
		if result == "" {
			t.Error("expected non-empty result")
		}
		if !containsStr(result, "env") {
			t.Errorf("expected result to contain 'env', got %s", result)
		}
	})

	t.Run("upper_case", func(t *testing.T) {
		result := resolvePattern("{PATH_UPPER}", "/admin")
		if result != "/ADMIN" {
			t.Errorf("expected /ADMIN, got %s", result)
		}
	})

	t.Run("mixed_case", func(t *testing.T) {
		result := mixedCase("/actuator/env")
		if result != "/Actuator/Env" {
			t.Errorf("expected /Actuator/Env, got %s", result)
		}
	})
}

func extractPaths(variants []Variant) []string {
	var paths []string
	for _, v := range variants {
		paths = append(paths, v.Path)
	}
	return paths
}

func filterWithHeaders(variants []Variant) []Variant {
	var result []Variant
	for _, v := range variants {
		if len(v.Headers) > 0 {
			result = append(result, v)
		}
	}
	return result
}

func assertContains(t *testing.T, paths []string, expected string) {
	t.Helper()
	for _, p := range paths {
		if p == expected {
			return
		}
	}
	t.Errorf("expected paths to contain %q", expected)
}

func containsStr(s, substr string) bool {
	return len(s) > 0 && len(substr) > 0 &&
		(s == substr || len(s) >= len(substr) && searchStr(s, substr))
}

func searchStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
