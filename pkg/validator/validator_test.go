package validator

import (
	"net/http"
	"testing"

	"github.com/nghia/java-path-scanner/pkg/httpclient"
)

func TestValidatorClassification(t *testing.T) {
	v := New()

	t.Run("200_true_positive", func(t *testing.T) {
		resp := &httpclient.Response{
			StatusCode:    200,
			Body:          []byte(`{"status":"UP","components":{"db":{"status":"UP"}}}`),
			ContentLength: 52,
			Headers:       http.Header{},
		}
		result := v.Validate("http://example.com", resp)
		if !result.IsTruePositive {
			t.Error("expected true positive for 200 with content")
		}
		if result.Classification != "true_positive" {
			t.Errorf("expected true_positive, got %s", result.Classification)
		}
	})

	t.Run("403_bypass_candidate", func(t *testing.T) {
		resp := &httpclient.Response{
			StatusCode:    403,
			Body:          []byte("Forbidden"),
			ContentLength: 9,
			Headers:       http.Header{},
		}
		result := v.Validate("http://example.com", resp)
		if result.IsTruePositive {
			t.Error("403 should not be true positive")
		}
		if result.Classification != "bypass_candidate" {
			t.Errorf("expected bypass_candidate, got %s", result.Classification)
		}
	})

	t.Run("waf_block_detected", func(t *testing.T) {
		resp := &httpclient.Response{
			StatusCode:    403,
			Body:          []byte("Access Denied - Your request has been blocked by our security policy"),
			ContentLength: 69,
			Headers:       http.Header{},
		}
		result := v.Validate("http://example.com", resp)
		if result.Classification != "waf_block" {
			t.Errorf("expected waf_block, got %s", result.Classification)
		}
	})

	t.Run("200_too_small", func(t *testing.T) {
		resp := &httpclient.Response{
			StatusCode:    200,
			Body:          []byte("ok"),
			ContentLength: 2,
			Headers:       http.Header{},
		}
		result := v.Validate("http://example.com", resp)
		if result.IsTruePositive {
			t.Error("small 200 should not be true positive")
		}
	})

	t.Run("405_method_not_allowed", func(t *testing.T) {
		resp := &httpclient.Response{
			StatusCode:    405,
			Body:          []byte("Method Not Allowed"),
			ContentLength: 18,
			Headers:       http.Header{},
		}
		result := v.Validate("http://example.com", resp)
		if !result.IsTruePositive {
			t.Error("405 should be true positive (endpoint exists)")
		}
	})

	t.Run("error_response", func(t *testing.T) {
		resp := &httpclient.Response{
			Err: http.ErrServerClosed,
		}
		result := v.Validate("http://example.com", resp)
		if result.IsTruePositive {
			t.Error("error should not be true positive")
		}
		if result.Classification != "error" {
			t.Errorf("expected error, got %s", result.Classification)
		}
	})
}

func TestSecretDetection(t *testing.T) {
	v := New()

	t.Run("finds_secrets", func(t *testing.T) {
		resp := &httpclient.Response{
			StatusCode:    200,
			Body:          []byte(`spring.datasource.password=SuperSecret123!`),
			ContentLength: 43,
			Headers:       http.Header{},
		}
		secrets := v.CheckSecrets(resp)
		if len(secrets) == 0 {
			t.Error("expected secrets to be found")
		}
	})

	t.Run("finds_jdbc_url", func(t *testing.T) {
		resp := &httpclient.Response{
			StatusCode:    200,
			Body:          []byte(`{"url":"jdbc:mysql://db.internal:3306/app"}`),
			ContentLength: 45,
			Headers:       http.Header{},
		}
		secrets := v.CheckSecrets(resp)
		found := false
		for _, s := range secrets {
			if containsStr(s, "jdbc_url") {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected jdbc_url secret, got %v", secrets)
		}
	})

	t.Run("ignores_masked_values", func(t *testing.T) {
		resp := &httpclient.Response{
			StatusCode:    200,
			Body:          []byte(`password=******`),
			ContentLength: 15,
			Headers:       http.Header{},
		}
		secrets := v.CheckSecrets(resp)
		if len(secrets) > 0 {
			t.Errorf("should not detect masked values, got %v", secrets)
		}
	})
}

func TestInfoLeakDetection(t *testing.T) {
	v := New()

	t.Run("stack_trace", func(t *testing.T) {
		resp := &httpclient.Response{
			StatusCode:    500,
			Body:          []byte(`java.lang.NullPointerException at com.example.Service.process(Service.java:42)`),
			ContentLength: 80,
			Headers:       http.Header{},
		}
		result := v.Validate("http://example.com", resp)
		if result.Classification != "info_leak" {
			t.Errorf("expected info_leak, got %s", result.Classification)
		}
	})
}

func containsStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
