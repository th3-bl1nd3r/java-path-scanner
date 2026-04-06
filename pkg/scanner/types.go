package scanner

import (
	"sync"
	"sync/atomic"

	"github.com/th3-bl1nd3r/java-path-scanner/pkg/httpclient"
)

// PathResult represents the result of scanning a single path.
type PathResult struct {
	Target        string
	Path          string
	URL           string
	StatusCode    int
	ContentLength int
	Technology    string
	Info          string
	Severity      string
	Response      *httpclient.Response
	BypassUsed    string
}

// IsAccessible returns true for 2xx status codes.
func (pr *PathResult) IsAccessible() bool {
	return pr.StatusCode >= 200 && pr.StatusCode < 300
}

// IsBypassCandidate returns true for 401/403 status codes.
func (pr *PathResult) IsBypassCandidate() bool {
	return pr.StatusCode == 401 || pr.StatusCode == 403
}

// IsInteresting returns true for responses worth investigating.
func (pr *PathResult) IsInteresting() bool {
	switch pr.StatusCode {
	case 200, 301, 302, 401, 403, 405, 500, 502, 503:
		return true
	}
	return false
}

// PathEntry is a path to scan with its metadata.
type PathEntry struct {
	Path       string
	Technology string
	Info       string
	Severity   string
}

// ScanProgress tracks scan progress for a target.
type ScanProgress struct {
	TotalPaths       int
	Scanned          int32
	Errors           int32
	Accessible       []*PathResult
	BypassCandidates []*PathResult
	Interesting      []*PathResult
	mu               sync.Mutex
}

// RecordAccessible adds an accessible result (thread-safe).
func (sp *ScanProgress) RecordAccessible(r *PathResult) {
	sp.mu.Lock()
	sp.Accessible = append(sp.Accessible, r)
	sp.mu.Unlock()
}

// RecordBypassCandidate adds a bypass candidate (thread-safe).
func (sp *ScanProgress) RecordBypassCandidate(r *PathResult) {
	sp.mu.Lock()
	sp.BypassCandidates = append(sp.BypassCandidates, r)
	sp.mu.Unlock()
}

// RecordInteresting adds an interesting result (thread-safe).
func (sp *ScanProgress) RecordInteresting(r *PathResult) {
	sp.mu.Lock()
	sp.Interesting = append(sp.Interesting, r)
	sp.mu.Unlock()
}

// IncrScanned atomically increments the scanned counter.
func (sp *ScanProgress) IncrScanned() {
	atomic.AddInt32(&sp.Scanned, 1)
}

// IncrErrors atomically increments the error counter.
func (sp *ScanProgress) IncrErrors() {
	atomic.AddInt32(&sp.Errors, 1)
}
