package httpclient

import (
	"context"
	"crypto/tls"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"sync/atomic"
	"time"

	"github.com/projectdiscovery/ratelimit"
	retryablehttp "github.com/projectdiscovery/retryablehttp-go"
)

// Client wraps retryablehttp with rate limiting and custom configuration.
type Client struct {
	httpClient   *retryablehttp.Client
	options      *Options
	rateLimiter  *ratelimit.Limiter
	requestCount int64
}

// NewClient creates a new HTTP client with the given options.
func NewClient(opts *Options, limiter *ratelimit.Limiter) (*Client, error) {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: !opts.VerifySSL, //nolint:gosec
		},
		MaxIdleConns:        opts.Concurrency,
		MaxIdleConnsPerHost: opts.Concurrency,
		IdleConnTimeout:     30 * time.Second,
		DisableKeepAlives:   false,
	}

	if opts.Proxy != "" {
		proxyURL, err := url.Parse(opts.Proxy)
		if err != nil {
			return nil, err
		}
		transport.Proxy = http.ProxyURL(proxyURL)
	}

	retryClient := retryablehttp.NewClient(retryablehttp.Options{
		RetryMax:     opts.MaxRetries,
		Timeout:      opts.Timeout,
		HttpClient: &http.Client{
			Transport: transport,
			Timeout:   opts.Timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if !opts.FollowRedirects {
					return http.ErrUseLastResponse
				}
				if len(via) >= opts.MaxRedirects {
					return http.ErrUseLastResponse
				}
				return nil
			},
		},
	})

	return &Client{
		httpClient:  retryClient,
		options:     opts,
		rateLimiter: limiter,
	}, nil
}

// Get sends a GET request.
func (c *Client) Get(ctx context.Context, targetURL string, extraHeaders ...map[string]string) *Response {
	return c.Do(ctx, http.MethodGet, targetURL, "", mergeHeaders(extraHeaders...))
}

// Post sends a POST request.
func (c *Client) Post(ctx context.Context, targetURL, body string, extraHeaders ...map[string]string) *Response {
	return c.Do(ctx, http.MethodPost, targetURL, body, mergeHeaders(extraHeaders...))
}

// Do sends an arbitrary HTTP request.
func (c *Client) Do(ctx context.Context, method, targetURL, body string, headers map[string]string) *Response {
	if c.rateLimiter != nil {
		c.rateLimiter.Take()
	}

	atomic.AddInt64(&c.requestCount, 1)

	start := time.Now()
	resp := &Response{URL: targetURL}

	req, err := retryablehttp.NewRequestWithContext(ctx, method, targetURL, nil)
	if err != nil {
		resp.Err = err
		return resp
	}

	// Set User-Agent
	if len(c.options.UserAgents) > 0 {
		ua := c.options.UserAgents[rand.Intn(len(c.options.UserAgents))]
		req.Header.Set("User-Agent", ua)
	}

	// Set custom headers
	for k, v := range c.options.CustomHeaders {
		req.Header.Set(k, v)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	// Set cookies
	for k, v := range c.options.Cookies {
		req.AddCookie(&http.Cookie{Name: k, Value: v})
	}

	httpResp, err := c.httpClient.Do(req)
	elapsed := time.Since(start)
	resp.ElapsedMs = float64(elapsed.Milliseconds())

	if err != nil {
		resp.Err = err
		return resp
	}
	defer httpResp.Body.Close()

	bodyBytes, err := io.ReadAll(io.LimitReader(httpResp.Body, 10*1024*1024)) // 10MB limit
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

// RequestCount returns the total number of requests made.
func (c *Client) RequestCount() int64 {
	return atomic.LoadInt64(&c.requestCount)
}

// Close releases resources.
func (c *Client) Close() {
	// retryablehttp doesn't require explicit close
}

func mergeHeaders(extras ...map[string]string) map[string]string {
	merged := make(map[string]string)
	for _, h := range extras {
		for k, v := range h {
			merged[k] = v
		}
	}
	return merged
}
