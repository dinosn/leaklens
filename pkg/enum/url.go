package enum

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	"github.com/dinosn/leaklens/pkg/types"
	"golang.org/x/sync/errgroup"
)

// URLEnumerator downloads content from HTTP(S) URLs and enumerates it for scanning.
type URLEnumerator struct {
	URLs          []string
	URLCandidates [][]string
	MaxSize       int64
	httpClient    *http.Client
}

// NewURLEnumerator creates a new enumerator for HTTP(S) URLs.
// maxSize limits the maximum response body size per URL (0 = 20MB default).
func NewURLEnumerator(urls []string, maxSize int64) *URLEnumerator {
	candidates := make([][]string, 0, len(urls))
	for _, u := range urls {
		candidates = append(candidates, []string{u})
	}
	return NewURLEnumeratorWithCandidates(candidates, maxSize)
}

// NewURLEnumeratorWithCandidates creates a new enumerator for HTTP(S) URLs
// where each item can include fallback URLs for the same discovered resource.
func NewURLEnumeratorWithCandidates(candidates [][]string, maxSize int64) *URLEnumerator {
	if maxSize <= 0 {
		maxSize = 20 * 1024 * 1024
	}
	urls := make([]string, 0, len(candidates))
	normalized := make([][]string, 0, len(candidates))
	for _, group := range candidates {
		if len(group) == 0 {
			continue
		}
		urls = append(urls, group[0])
		normalized = append(normalized, group)
	}
	return &URLEnumerator{
		URLs:          urls,
		URLCandidates: normalized,
		MaxSize:       maxSize,
		httpClient:    newTLSFallbackHTTPClient(30 * time.Second),
	}
}

// Enumerate downloads each URL and invokes the callback with the content.
func (e *URLEnumerator) Enumerate(ctx context.Context, callback func(content []byte, blobID types.BlobID, prov types.Provenance) error) error {
	numWorkers := runtime.NumCPU()
	if numWorkers > len(e.URLs) {
		numWorkers = len(e.URLs)
	}
	if numWorkers < 1 {
		numWorkers = 1
	}

	urlsCh := make(chan []string, numWorkers*2)

	origCtx := ctx
	g, ctx := errgroup.WithContext(ctx)
	var successCount atomic.Int64

	g.Go(func() error {
		defer close(urlsCh)
		for _, u := range e.URLCandidates {
			select {
			case urlsCh <- u:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		return nil
	})

	for i := 0; i < numWorkers; i++ {
		g.Go(func() error {
			for candidates := range urlsCh {
				ok, err := e.processURLCandidates(ctx, candidates, callback)
				if err != nil {
					return err
				}
				if ok {
					successCount.Add(1)
				}
			}
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return err
	}
	if origCtx.Err() != nil {
		return origCtx.Err()
	}
	if len(e.URLCandidates) > 0 && successCount.Load() == 0 {
		return fmt.Errorf("all URL fetches failed")
	}
	return nil
}

func (e *URLEnumerator) processURLCandidates(ctx context.Context, candidates []string, callback func(content []byte, blobID types.BlobID, prov types.Provenance) error) (bool, error) {
	if len(candidates) == 0 {
		return false, nil
	}

	var failures []string
	for i, rawURL := range candidates {
		ok, reason, err := e.processURL(ctx, rawURL, callback)
		if err != nil {
			return false, err
		}
		if ok {
			if i > 0 {
				warnf("  repaired: %s -> %s\n", candidates[0], rawURL)
			}
			return true, nil
		}
		if reason != "" {
			failures = append(failures, fmt.Sprintf("%s for %s", reason, rawURL))
		}
	}

	if len(failures) == 0 {
		return false, nil
	}
	if len(candidates) == 1 {
		warnf("warning: %s\n", failures[0])
		return false, nil
	}
	warnf("warning: all candidate URLs failed for %s: %s\n", candidates[0], strings.Join(failures, "; "))
	return false, nil
}

func (e *URLEnumerator) processURL(ctx context.Context, rawURL string, callback func(content []byte, blobID types.BlobID, prov types.Provenance) error) (bool, string, error) {
	select {
	case <-ctx.Done():
		return false, "", ctx.Err()
	default:
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return false, fmt.Sprintf("invalid URL: %v", err), nil
	}

	resp, err := e.httpClient.Do(req)
	if err != nil {
		return false, fmt.Sprintf("failed to fetch: %v", err), nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Sprintf("HTTP %d", resp.StatusCode), nil
	}

	reader := io.LimitReader(resp.Body, e.MaxSize+1)
	var buf bytes.Buffer
	n, err := io.Copy(&buf, reader)
	if err != nil {
		return false, fmt.Sprintf("error reading: %v", err), nil
	}

	if n > e.MaxSize {
		return false, fmt.Sprintf("response too large (%d bytes)", n), nil
	}

	content := buf.Bytes()
	if len(content) == 0 {
		return true, "", nil
	}

	if isBinary(content) {
		return true, "", nil
	}

	blobID := types.ComputeBlobID(content)
	prov := types.URLProvenance{URL: rawURL}

	return true, "", callback(content, blobID, prov)
}
