package httpclient

import (
	"context"
	"io"
	"strings"
	"sync/atomic"
	"time"

	"github.com/projectdiscovery/ratelimit"
	"github.com/projectdiscovery/rawhttp"
)

// RawClient sends HTTP requests preserving raw path encoding.
// This is essential for bypass payloads like /admin/..;/actuator/env
// or /%252e%252e/admin where standard Go http.Client would normalize the path.
type RawClient struct {
	client      *rawhttp.Client
	options     *Options
	rateLimiter *ratelimit.Limiter
	reqCount    int64
}

// NewRawClient creates a new raw HTTP client.
func NewRawClient(opts *Options, limiter *ratelimit.Limiter) *RawClient {
	rawOpts := rawhttp.DefaultOptions
	rawOpts.Timeout = opts.Timeout
	rawOpts.FollowRedirects = opts.FollowRedirects

	client := rawhttp.NewClient(rawOpts)

	return &RawClient{
		client:      client,
		options:     opts,
		rateLimiter: limiter,
	}
}

// Get sends a raw GET request, preserving the exact path encoding.
func (rc *RawClient) Get(_ context.Context, targetURL string, headers map[string]string) *Response {
	if rc.rateLimiter != nil {
		rc.rateLimiter.Take()
	}

	atomic.AddInt64(&rc.reqCount, 1)
	start := time.Now()
	resp := &Response{URL: targetURL}

	path := extractPath(targetURL)
	rawHeaders := buildRawHeaders(targetURL, headers, rc.options)

	httpResp, err := rc.client.DoRaw("GET", targetURL, path, rawHeaders, nil)
	elapsed := time.Since(start)
	resp.ElapsedMs = float64(elapsed.Milliseconds())

	if err != nil {
		resp.Err = err
		return resp
	}
	defer httpResp.Body.Close()

	bodyBytes, err := io.ReadAll(io.LimitReader(httpResp.Body, 10*1024*1024))
	if err != nil {
		resp.Err = err
		return resp
	}

	resp.StatusCode = httpResp.StatusCode
	resp.Headers = httpResp.Header
	resp.Body = bodyBytes
	resp.ContentLength = len(bodyBytes)

	return resp
}

// RequestCount returns the total requests sent.
func (rc *RawClient) RequestCount() int64 {
	return atomic.LoadInt64(&rc.reqCount)
}

func extractPath(rawURL string) string {
	idx := strings.Index(rawURL, "://")
	if idx == -1 {
		return rawURL
	}
	rest := rawURL[idx+3:]
	slashIdx := strings.Index(rest, "/")
	if slashIdx == -1 {
		return "/"
	}
	return rest[slashIdx:]
}

func buildRawHeaders(targetURL string, extra map[string]string, opts *Options) map[string][]string {
	headers := make(map[string][]string)

	// Host header
	idx := strings.Index(targetURL, "://")
	if idx != -1 {
		rest := targetURL[idx+3:]
		slashIdx := strings.Index(rest, "/")
		if slashIdx != -1 {
			headers["Host"] = []string{rest[:slashIdx]}
		} else {
			headers["Host"] = []string{rest}
		}
	}

	headers["Accept"] = []string{"*/*"}
	headers["Connection"] = []string{"close"}

	if len(opts.UserAgents) > 0 {
		headers["User-Agent"] = []string{opts.UserAgents[0]}
	}

	for k, v := range opts.CustomHeaders {
		headers[k] = []string{v}
	}
	for k, v := range extra {
		headers[k] = []string{v}
	}

	// Add cookies
	if len(opts.Cookies) > 0 {
		var parts []string
		for k, v := range opts.Cookies {
			parts = append(parts, k+"="+v)
		}
		headers["Cookie"] = []string{strings.Join(parts, "; ")}
	}

	return headers
}
