package httpclient

import (
	"net/http"
	"strings"
	"time"
)

// Response encapsulates an HTTP response with metadata.
type Response struct {
	URL           string
	StatusCode    int
	Headers       http.Header
	Body          []byte
	ContentLength int
	ElapsedMs     float64
	RedirectChain []string
	Err           error
}

// BodyString returns the response body as a string.
func (r *Response) BodyString() string {
	return string(r.Body)
}

// HeaderGet returns the first value for a header key (case-insensitive).
func (r *Response) HeaderGet(key string) string {
	if r.Headers == nil {
		return ""
	}
	return r.Headers.Get(key)
}

// HasHeaderValue checks if a header contains a substring (case-insensitive).
func (r *Response) HasHeaderValue(key, substr string) bool {
	val := r.HeaderGet(key)
	return val != "" && strings.Contains(strings.ToLower(val), strings.ToLower(substr))
}

// IsSuccess returns true for 2xx status codes.
func (r *Response) IsSuccess() bool {
	return r.StatusCode >= 200 && r.StatusCode < 300
}

// IsForbidden returns true for 401/403 status codes.
func (r *Response) IsForbidden() bool {
	return r.StatusCode == 401 || r.StatusCode == 403
}

// IsNotFound returns true for 404 status codes.
func (r *Response) IsNotFound() bool {
	return r.StatusCode == 404
}

// Options configures the HTTP client.
type Options struct {
	Concurrency     int
	Timeout         time.Duration
	MaxRetries      int
	VerifySSL       bool
	FollowRedirects bool
	MaxRedirects    int
	Proxy           string
	CustomHeaders   map[string]string
	Cookies         map[string]string
	UserAgents      []string
	RateLimit       int
	Delay           time.Duration
}

// DefaultOptions returns sensible HTTP client defaults.
func DefaultOptions() *Options {
	return &Options{
		Concurrency:     50,
		Timeout:         10 * time.Second,
		MaxRetries:      2,
		VerifySSL:       true,
		FollowRedirects: false,
		MaxRedirects:    5,
		RateLimit:       50,
		UserAgents: []string{
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		},
	}
}
