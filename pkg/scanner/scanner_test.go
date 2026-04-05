package scanner

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/projectdiscovery/ratelimit"

	"github.com/nghia/java-path-scanner/internal/knowledge"
	"github.com/nghia/java-path-scanner/pkg/httpclient"
)

func setupMockServer() *httptest.Server {
	mux := http.NewServeMux()

	// Spring Boot Actuator endpoints
	mux.HandleFunc("/actuator", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"_links":{"self":{"href":"/actuator"},"health":{"href":"/actuator/health"},"env":{"href":"/actuator/env"}}}`)
	})
	mux.HandleFunc("/actuator/env", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"activeProfiles":["prod"],"propertySources":[{"name":"systemProperties","properties":{"spring.datasource.url":{"value":"jdbc:mysql://db.internal:3306/app"}}}]}`)
	})
	mux.HandleFunc("/actuator/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"status":"UP"}`)
	})

	// 403 for admin
	mux.HandleFunc("/admin", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
		fmt.Fprint(w, "Access Denied")
	})

	// Swagger
	mux.HandleFunc("/swagger-ui.html", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<html><head><title>Swagger UI</title></head><body>Swagger UI loaded successfully with API documentation</body></html>`)
	})

	// Root with Java server headers
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Apache-Coyote/1.1")
		w.Header().Set("Set-Cookie", "JSESSIONID=abc123; Path=/")
		fmt.Fprint(w, `<html><body>Welcome</body></html>`)
	})

	// Everything else: 404
	return httptest.NewServer(mux)
}

func createTestClient(t *testing.T) (*httpclient.Client, *ratelimit.Limiter) {
	t.Helper()
	ctx := context.Background()
	limiter := ratelimit.New(ctx, 100, time.Second)
	opts := httpclient.DefaultOptions()
	opts.VerifySSL = false
	opts.MaxRetries = 0
	client, err := httpclient.NewClient(opts, limiter)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	return client, limiter
}

func TestBruteforcerScanTarget(t *testing.T) {
	server := setupMockServer()
	defer server.Close()

	client, limiter := createTestClient(t)
	defer limiter.Stop()

	kb, err := knowledge.Load()
	if err != nil {
		t.Fatalf("failed to load KB: %v", err)
	}

	bf := NewBruteforcer(&kb.Paths)
	entries := []PathEntry{
		{Path: "/actuator", Technology: "spring_boot_actuator", Info: "Actuator index", Severity: "medium"},
		{Path: "/actuator/env", Technology: "spring_boot_actuator", Info: "Env endpoint", Severity: "critical"},
		{Path: "/actuator/health", Technology: "spring_boot_actuator", Info: "Health check", Severity: "low"},
		{Path: "/admin", Technology: "generic", Info: "Admin panel", Severity: "high"},
		{Path: "/swagger-ui.html", Technology: "swagger_api_docs", Info: "Swagger UI", Severity: "medium"},
		{Path: "/nonexistent", Technology: "generic", Info: "Should 404", Severity: "low"},
	}

	ctx := context.Background()
	progress := bf.ScanTarget(ctx, server.URL, client, entries, 10, nil)

	if progress.TotalPaths != 6 {
		t.Errorf("expected 6 total paths, got %d", progress.TotalPaths)
	}

	// Check accessible paths (200)
	accessiblePaths := make(map[string]bool)
	for _, r := range progress.Accessible {
		accessiblePaths[r.Path] = true
	}

	for _, expected := range []string{"/actuator", "/actuator/env", "/actuator/health", "/swagger-ui.html"} {
		if !accessiblePaths[expected] {
			t.Errorf("expected %s to be accessible", expected)
		}
	}

	// Check bypass candidates (403)
	bypassPaths := make(map[string]bool)
	for _, r := range progress.BypassCandidates {
		bypassPaths[r.Path] = true
	}

	if !bypassPaths["/admin"] {
		t.Error("expected /admin to be a bypass candidate")
	}
}

func TestBruteforcerGetPathsForGroups(t *testing.T) {
	kb, err := knowledge.Load()
	if err != nil {
		t.Fatalf("failed to load KB: %v", err)
	}

	bf := NewBruteforcer(&kb.Paths)
	entries := bf.GetPathsForGroups([]string{"spring_boot_actuator"})

	if len(entries) == 0 {
		t.Fatal("expected entries for spring_boot_actuator")
	}

	// Check that paths start with /
	for _, e := range entries {
		if !strings.HasPrefix(e.Path, "/") {
			t.Errorf("path should start with /: %s", e.Path)
		}
	}

	// Check that technology is set
	for _, e := range entries {
		if e.Technology != "spring_boot_actuator" {
			t.Errorf("expected technology spring_boot_actuator, got %s", e.Technology)
		}
	}
}
