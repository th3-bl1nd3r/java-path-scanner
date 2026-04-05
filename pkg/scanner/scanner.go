package scanner

import (
	"context"
	"strings"
	"sync"

	"github.com/nghia/java-path-scanner/internal/knowledge"
	"github.com/nghia/java-path-scanner/pkg/httpclient"
	"github.com/nghia/java-path-scanner/pkg/urlutil"
)

// PathCallback is invoked for each scanned path.
type PathCallback func(result *PathResult)

// Bruteforcer discovers exposed paths on targets.
type Bruteforcer struct {
	pathsDB *knowledge.PathsDB
}

// NewBruteforcer creates a new path bruteforcer.
func NewBruteforcer(db *knowledge.PathsDB) *Bruteforcer {
	return &Bruteforcer{pathsDB: db}
}

// GetPathsForGroups returns all path entries for the given technology groups,
// including context-prefixed variants. Deduplicates paths.
func (b *Bruteforcer) GetPathsForGroups(groups []string) []PathEntry {
	var entries []PathEntry
	seen := make(map[string]bool)

	for _, group := range groups {
		groupData, ok := (*b.pathsDB)[group]
		if !ok {
			continue
		}

		for _, p := range groupData.Paths {
			if seen[p.Path] {
				continue
			}
			seen[p.Path] = true
			entries = append(entries, PathEntry{
				Path:       p.Path,
				Technology: group,
				Info:       p.Info,
				Severity:   p.Severity,
			})

			// Generate context-prefixed variants
			for _, prefix := range groupData.ContextPrefixes {
				prefix = strings.TrimRight(prefix, "/")
				if prefix == "" {
					continue
				}
				prefixed := prefix + p.Path
				if !seen[prefixed] {
					seen[prefixed] = true
					entries = append(entries, PathEntry{
						Path:       prefixed,
						Technology: group,
						Info:       "[" + prefix + "] " + p.Info,
						Severity:   p.Severity,
					})
				}
			}
		}
	}

	return entries
}

// ScanTarget scans a target for all path entries using a worker pool.
func (b *Bruteforcer) ScanTarget(
	ctx context.Context,
	target string,
	client *httpclient.Client,
	entries []PathEntry,
	concurrency int,
	callback PathCallback,
) *ScanProgress {
	progress := &ScanProgress{TotalPaths: len(entries)}

	var wg sync.WaitGroup
	workCh := make(chan PathEntry, len(entries))

	// Start workers
	workers := concurrency
	if workers <= 0 {
		workers = 50
	}
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for entry := range workCh {
				if ctx.Err() != nil {
					return
				}
				b.checkPath(ctx, target, client, entry, progress, callback)
			}
		}()
	}

	// Feed work
	for _, entry := range entries {
		select {
		case workCh <- entry:
		case <-ctx.Done():
			break
		}
	}
	close(workCh)
	wg.Wait()

	return progress
}

func (b *Bruteforcer) checkPath(
	ctx context.Context,
	target string,
	client *httpclient.Client,
	entry PathEntry,
	progress *ScanProgress,
	callback PathCallback,
) {
	targetURL := urlutil.BuildURL(target, entry.Path)
	resp := client.Get(ctx, targetURL)
	progress.IncrScanned()

	if resp.Err != nil {
		progress.IncrErrors()
		return
	}

	result := &PathResult{
		Target:        target,
		Path:          entry.Path,
		URL:           targetURL,
		StatusCode:    resp.StatusCode,
		ContentLength: resp.ContentLength,
		Technology:    entry.Technology,
		Info:          entry.Info,
		Severity:      entry.Severity,
		Response:      resp,
	}

	if result.IsAccessible() {
		progress.RecordAccessible(result)
	} else if result.IsBypassCandidate() {
		progress.RecordBypassCandidate(result)
	}

	if result.IsInteresting() && !result.IsAccessible() {
		progress.RecordInteresting(result)
	}

	if callback != nil {
		callback(result)
	}
}
