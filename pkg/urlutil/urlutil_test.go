package urlutil

import (
	"testing"
)

func TestNormalizeBaseURL(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"https://example.com", "https://example.com"},
		{"https://example.com/", "https://example.com"},
		{"http://example.com///", "http://example.com"},
		{"example.com", "https://example.com"},
		{"example.com:8080", "https://example.com:8080"},
		{"  https://example.com  ", "https://example.com"},
		{"", ""},
	}
	for _, tt := range tests {
		got := NormalizeBaseURL(tt.input)
		if got != tt.expected {
			t.Errorf("NormalizeBaseURL(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestBuildURL(t *testing.T) {
	tests := []struct {
		base     string
		path     string
		expected string
	}{
		{"https://example.com", "/actuator/env", "https://example.com/actuator/env"},
		{"https://example.com/", "actuator/env", "https://example.com/actuator/env"},
		{"example.com", "/admin", "https://example.com/admin"},
	}
	for _, tt := range tests {
		got := BuildURL(tt.base, tt.path)
		if got != tt.expected {
			t.Errorf("BuildURL(%q, %q) = %q, want %q", tt.base, tt.path, got, tt.expected)
		}
	}
}

func TestBuildRawURL(t *testing.T) {
	tests := []struct {
		base     string
		path     string
		expected string
	}{
		{"https://example.com", "/admin/..;/actuator/env", "https://example.com/admin/..;/actuator/env"},
		{"https://example.com", "/%2e%2e/admin", "https://example.com/%2e%2e/admin"},
		{"https://example.com", "/static/..%2f..%2factuator/env", "https://example.com/static/..%2f..%2factuator/env"},
	}
	for _, tt := range tests {
		got := BuildRawURL(tt.base, tt.path)
		if got != tt.expected {
			t.Errorf("BuildRawURL(%q, %q) = %q, want %q", tt.base, tt.path, got, tt.expected)
		}
	}
}

func TestApplyContextPrefix(t *testing.T) {
	paths := ApplyContextPrefix("/actuator/env", []string{"/app", "/myservice"})
	if len(paths) != 3 {
		t.Fatalf("expected 3 paths, got %d", len(paths))
	}
	if paths[0] != "/actuator/env" {
		t.Errorf("first path should be original, got %s", paths[0])
	}
	if paths[1] != "/app/actuator/env" {
		t.Errorf("expected /app/actuator/env, got %s", paths[1])
	}
	if paths[2] != "/myservice/actuator/env" {
		t.Errorf("expected /myservice/actuator/env, got %s", paths[2])
	}
}

func TestParseTarget(t *testing.T) {
	scheme, host, port, err := ParseTarget("https://example.com:8443")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if scheme != "https" || host != "example.com" || port != 8443 {
		t.Errorf("got scheme=%s host=%s port=%d", scheme, host, port)
	}

	scheme, host, port, err = ParseTarget("http://localhost")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if port != 80 {
		t.Errorf("expected port 80, got %d", port)
	}
}
