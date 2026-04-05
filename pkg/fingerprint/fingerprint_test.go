package fingerprint

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/projectdiscovery/ratelimit"

	"github.com/nghia/java-path-scanner/internal/knowledge"
	"github.com/nghia/java-path-scanner/pkg/httpclient"
)

func setupFingerprintServer() *httptest.Server {
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Apache-Coyote/1.1")
		w.Header().Set("X-Application-Context", "myapp:prod:8080")
		w.Header().Set("Set-Cookie", "JSESSIONID=abc123; Path=/")
		fmt.Fprint(w, `<html><body>Welcome</body></html>`)
	})

	mux.HandleFunc("/___nonexistent_path_scanner_404___", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
		fmt.Fprint(w, `{"timestamp":"2024-01-01","status":404,"error":"Not Found","message":"","path":"/___nonexistent_path_scanner_404___"}`)
	})

	mux.HandleFunc("/actuator/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"status":"UP"}`)
	})

	return httptest.NewServer(mux)
}

func TestFingerprintEngine(t *testing.T) {
	server := setupFingerprintServer()
	defer server.Close()

	kb, err := knowledge.Load()
	if err != nil {
		t.Fatalf("failed to load KB: %v", err)
	}

	engine := NewEngine(&kb.Fingerprints)
	ctx := context.Background()
	limiter := ratelimit.New(ctx, 100, time.Second)
	defer limiter.Stop()

	opts := httpclient.DefaultOptions()
	opts.VerifySSL = false
	opts.MaxRetries = 0
	client, err := httpclient.NewClient(opts, limiter)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	result, err := engine.Fingerprint(ctx, server.URL, client)
	if err != nil {
		t.Fatalf("fingerprint error: %v", err)
	}

	t.Run("detects_tomcat", func(t *testing.T) {
		techs := result.DetectedTechs()
		found := false
		for _, tech := range techs {
			if tech == "tomcat" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected tomcat detection, got techs: %v", techs)
		}
	})

	t.Run("detects_spring_boot", func(t *testing.T) {
		techs := result.DetectedTechs()
		found := false
		for _, tech := range techs {
			if tech == "spring_boot_actuator" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected spring_boot_actuator detection, got techs: %v", techs)
		}
	})

	t.Run("server_header_captured", func(t *testing.T) {
		if result.ServerHeader == "" {
			t.Error("expected server header to be captured")
		}
		if result.ServerHeader != "Apache-Coyote/1.1" {
			t.Errorf("expected Apache-Coyote/1.1, got %s", result.ServerHeader)
		}
	})

	t.Run("path_groups_include_spring", func(t *testing.T) {
		groups := engine.GetPathGroups(result)
		found := false
		for _, g := range groups {
			if g == "spring_boot_actuator" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected spring_boot_actuator in path groups, got %v", groups)
		}
	})

	t.Run("path_groups_include_generic", func(t *testing.T) {
		groups := engine.GetPathGroups(result)
		found := false
		for _, g := range groups {
			if g == "generic" {
				found = true
				break
			}
		}
		if !found {
			t.Error("expected generic in path groups")
		}
	})
}

func TestHeaderAnalysis(t *testing.T) {
	kb, err := knowledge.Load()
	if err != nil {
		t.Fatalf("failed to load KB: %v", err)
	}

	engine := NewEngine(&kb.Fingerprints)

	t.Run("jenkins_header", func(t *testing.T) {
		result := &Result{Technologies: make(map[string]float64)}
		resp := &httpclient.Response{
			Headers: http.Header{
				"X-Jenkins": []string{"2.401.1"},
			},
		}
		engine.analyzeHeaders(resp, result)
		if _, ok := result.Technologies["jenkins"]; !ok {
			t.Error("expected jenkins detection from X-Jenkins header")
		}
	})

	t.Run("exclude_non_java", func(t *testing.T) {
		result := &Result{Technologies: make(map[string]float64)}
		resp := &httpclient.Response{
			Headers: http.Header{
				"X-Powered-By": []string{"Express"},
			},
		}
		engine.analyzeHeaders(resp, result)
		if _, ok := result.Technologies["nodejs"]; ok {
			t.Error("nodejs should be excluded, not detected as a target")
		}
	})
}

func TestWAFDetection(t *testing.T) {
	kb, err := knowledge.Load()
	if err != nil {
		t.Fatalf("failed to load KB: %v", err)
	}

	engine := NewEngine(&kb.Fingerprints)

	t.Run("cloudflare_waf", func(t *testing.T) {
		result := &Result{Technologies: make(map[string]float64)}
		resp := &httpclient.Response{
			Headers: http.Header{
				"Cf-Ray": []string{"abc123"},
			},
		}
		engine.detectWAF(resp, result)
		if result.WAFDetected != "Cloudflare" {
			t.Errorf("expected Cloudflare WAF, got %s", result.WAFDetected)
		}
	})
}
