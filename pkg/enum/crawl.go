package enum

import (
	"context"
	"fmt"
	"math"
	"net/url"
	"os"
	"path"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/projectdiscovery/katana/pkg/engine/hybrid"
	"github.com/projectdiscovery/katana/pkg/engine/standard"
	katanaoutput "github.com/projectdiscovery/katana/pkg/output"
	katanatypes "github.com/projectdiscovery/katana/pkg/types"
	"github.com/projectdiscovery/katana/pkg/utils/queue"

	"github.com/projectdiscovery/gologger"
	gologgerlevels "github.com/projectdiscovery/gologger/levels"
	gologgerwriter "github.com/projectdiscovery/gologger/writer"

	"github.com/dinosn/leaklens/pkg/types"
)

// CrawlEnumerator uses katana to crawl a target URL and enumerate discovered
// files for scanning. By default it filters for JavaScript files.
type CrawlEnumerator struct {
	TargetURL          string
	BaseURL            string
	MaxDepth           int
	Concurrency        int
	RateLimit          int
	HostRateLimit      int
	Timeout            time.Duration
	Headless           bool
	JSCrawl            bool
	Extensions         []string
	Scope              string
	MaxSize            int64
	MaxDomainPages     int
	ChromeDataDir      string
	ChromeWSURL        string
	SystemChromePath   string
	NoIncognito        bool
	AutomaticFormFill  bool
	AuthCredentials    string
	UseInstalledChrome bool
}

// CrawlConfig holds configuration for the crawl enumerator.
type CrawlConfig struct {
	TargetURL          string
	BaseURL            string
	MaxDepth           int
	Concurrency        int
	RateLimit          int
	HostRateLimit      int
	Timeout            time.Duration
	Headless           bool
	JSCrawl            bool
	Extensions         []string
	Scope              string
	MaxSize            int64
	MaxDomainPages     int
	ChromeDataDir      string
	ChromeWSURL        string
	SystemChromePath   string
	NoIncognito        bool
	AutomaticFormFill  bool
	AuthCredentials    string
	UseInstalledChrome bool
}

// NewCrawlEnumerator creates a new enumerator that crawls a target URL.
func NewCrawlEnumerator(cfg CrawlConfig) *CrawlEnumerator {
	if cfg.MaxDepth <= 0 {
		cfg.MaxDepth = 3
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 2
	}
	if cfg.Scope == "" {
		cfg.Scope = "rdn"
	}
	if len(cfg.Extensions) == 0 {
		cfg.Extensions = []string{"js", "json"}
	}
	if cfg.MaxSize <= 0 {
		cfg.MaxSize = 10 * 1024 * 1024
	}
	return &CrawlEnumerator{
		TargetURL:          cfg.TargetURL,
		BaseURL:            cfg.BaseURL,
		MaxDepth:           cfg.MaxDepth,
		Concurrency:        cfg.Concurrency,
		RateLimit:          cfg.RateLimit,
		HostRateLimit:      cfg.HostRateLimit,
		Timeout:            cfg.Timeout,
		Headless:           cfg.Headless,
		JSCrawl:            cfg.JSCrawl,
		Extensions:         cfg.Extensions,
		Scope:              cfg.Scope,
		MaxSize:            cfg.MaxSize,
		MaxDomainPages:     cfg.MaxDomainPages,
		ChromeDataDir:      cfg.ChromeDataDir,
		ChromeWSURL:        cfg.ChromeWSURL,
		SystemChromePath:   cfg.SystemChromePath,
		NoIncognito:        cfg.NoIncognito,
		AutomaticFormFill:  cfg.AutomaticFormFill,
		AuthCredentials:    cfg.AuthCredentials,
		UseInstalledChrome: cfg.UseInstalledChrome,
	}
}

// discardWriter is a gologger writer that discards all output.
type discardWriter struct{}

func (d *discardWriter) Write(data []byte, level gologgerlevels.Level) {}

// urlMatchesExtensions checks if a URL's path ends with one of the target extensions.
func urlMatchesExtensions(rawURL string, extensions []string) bool {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	ext := strings.TrimPrefix(path.Ext(parsed.Path), ".")
	if ext == "" {
		return false
	}
	ext = strings.ToLower(ext)
	for _, e := range extensions {
		if ext == strings.ToLower(e) {
			return true
		}
	}
	return false
}

// Enumerate crawls the target URL, collects discovered file URLs matching the
// configured extensions, then downloads and passes each file to the callback.
//
// Katana is used only for URL discovery (spidering). The actual content download
// is handled separately by URLEnumerator because katana may not fully fetch
// every resource it discovers (e.g. due to crawl timeouts or parse failures).
func (e *CrawlEnumerator) Enumerate(ctx context.Context, callback func(content []byte, blobID types.BlobID, prov types.Provenance) error) error {
	var mu sync.Mutex
	seen := make(map[string]struct{})
	var discoveredURLs []string
	var discoveredCandidates [][]string
	var acceptingResults atomic.Bool
	acceptingResults.Store(true)

	crawlRequestTimeout := 30
	if e.Timeout > 0 && e.Timeout < time.Duration(crawlRequestTimeout)*time.Second {
		crawlRequestTimeout = max(1, int(math.Ceil(e.Timeout.Seconds())))
	}

	// Do NOT set ExtensionsMatch here: katana uses it to filter which URLs to
	// visit (not just which to report), so setting it to ["js"] would prevent
	// katana from visiting HTML pages and it would never discover JS links.
	// Instead we filter by extension in the OnResult callback.
	options := &katanatypes.Options{
		MaxDepth:            e.MaxDepth,
		FieldScope:          e.Scope,
		BodyReadSize:        math.MaxInt,
		RateLimit:           e.RateLimit,
		HostRateLimit:       e.HostRateLimit,
		Concurrency:         e.Concurrency,
		Parallelism:         e.Concurrency,
		Strategy:            queue.BreadthFirst.String(),
		Timeout:             crawlRequestTimeout,
		TimeStable:          1,
		Retries:             1,
		ScrapeJSResponses:   e.JSCrawl,
		MaxDomainPages:      e.MaxDomainPages,
		ChromeDataDir:       e.ChromeDataDir,
		ChromeWSUrl:         e.ChromeWSURL,
		SystemChromePath:    e.SystemChromePath,
		HeadlessNoIncognito: e.NoIncognito,
		AutomaticFormFill:   e.AutomaticFormFill,
		AuthCredentials:     e.AuthCredentials,
		UseInstalledChrome:  e.UseInstalledChrome,
		Silent:              true,
		OnResult: func(r katanaoutput.Result) {
			if !acceptingResults.Load() {
				return
			}
			if r.Request == nil {
				return
			}
			rawURL := r.Request.URL
			if rawURL == "" {
				return
			}
			if !urlMatchesExtensions(rawURL, e.Extensions) {
				return
			}
			candidates := e.urlCandidates(rawURL)
			key := strings.Join(candidates, "\x00")
			mu.Lock()
			defer mu.Unlock()
			if !acceptingResults.Load() {
				return
			}
			if _, dup := seen[key]; !dup {
				seen[key] = struct{}{}
				discoveredURLs = append(discoveredURLs, rawURL)
				discoveredCandidates = append(discoveredCandidates, candidates)
				fmt.Fprintf(os.Stderr, "  found: %s\n", rawURL)
			}
		},
	}

	if e.Timeout > 0 {
		options.CrawlDuration = e.Timeout
	}
	if e.Headless {
		options.Headless = true
	}

	// Suppress katana's own log output by replacing the gologger writer
	// with a discard writer. Restore the original writer after the crawl.
	origWriter := gologgerwriter.NewCLI()
	gologger.DefaultLogger.SetWriter(&discardWriter{})
	defer gologger.DefaultLogger.SetWriter(origWriter)

	crawlerOptions, err := katanatypes.NewCrawlerOptions(options)
	if err != nil {
		return fmt.Errorf("creating crawler options: %w", err)
	}
	defer crawlerOptions.Close()

	type crawler interface {
		Crawl(string) error
		Close() error
	}

	var engine crawler
	if e.Headless {
		engine, err = hybrid.New(crawlerOptions)
	} else {
		engine, err = standard.New(crawlerOptions)
	}
	if err != nil {
		return fmt.Errorf("creating crawler: %w", err)
	}

	var closeOnce sync.Once
	closeEngine := func() {
		closeOnce.Do(func() {
			if err := engine.Close(); err != nil {
				fmt.Fprintf(os.Stderr, "Crawl cleanup warning: %v\n", err)
			}
		})
	}
	defer closeEngine()

	mode := "standard"
	if e.Headless {
		mode = "headless"
	}
	fmt.Fprintf(os.Stderr, "Crawling %s (%s, depth=%d, extensions=%s)...\n",
		e.TargetURL, mode, e.MaxDepth, strings.Join(e.Extensions, ","))

	err, timedOut := e.runCrawlWithDeadline(ctx, engine, closeEngine)

	mu.Lock()
	acceptingResults.Store(false)
	finalURLs := append([]string(nil), discoveredURLs...)
	finalCandidates := append([][]string(nil), discoveredCandidates...)
	mu.Unlock()

	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if timedOut {
			fmt.Fprintf(os.Stderr, "Crawl stopped: timeout %s reached\n", e.Timeout)
		} else {
			// Crawl timeout or other non-fatal crawl errors: log and continue
			// with whatever URLs were discovered before the error.
			fmt.Fprintf(os.Stderr, "Crawl stopped: %v\n", err)
		}
	} else if timedOut {
		// Crawl timeout or other non-fatal crawl errors: log and continue
		// with whatever URLs were discovered before the error.
		fmt.Fprintf(os.Stderr, "Crawl stopped: timeout %s reached\n", e.Timeout)
	}

	if len(finalURLs) == 0 {
		fmt.Fprintf(os.Stderr, "Crawl complete: no matching files found\n")
		return nil
	}

	fmt.Fprintf(os.Stderr, "Crawl complete: discovered %d unique %s file(s), downloading and scanning...\n",
		len(finalURLs), strings.Join(e.Extensions, "/"))

	urlEnum := NewURLEnumeratorWithCandidates(finalCandidates, e.MaxSize)
	return urlEnum.Enumerate(ctx, callback)
}

func (e *CrawlEnumerator) runCrawlWithDeadline(ctx context.Context, engine interface {
	Crawl(string) error
}, closeEngine func()) (error, bool) {
	crawlErrCh := make(chan error, 1)
	go func() {
		crawlErrCh <- engine.Crawl(e.TargetURL)
	}()

	var timeoutCh <-chan time.Time
	var timer *time.Timer
	if e.Timeout > 0 {
		timer = time.NewTimer(e.Timeout)
		timeoutCh = timer.C
		defer timer.Stop()
	}

	select {
	case err := <-crawlErrCh:
		return err, false
	case <-ctx.Done():
		closeEngine()
		return ctx.Err(), false
	case <-timeoutCh:
		closeEngine()
		select {
		case err := <-crawlErrCh:
			return err, true
		case <-time.After(2 * time.Second):
			return nil, true
		}
	}
}

func (e *CrawlEnumerator) urlCandidates(rawURL string) []string {
	candidates := []string{rawURL}
	rawParsed, err := url.Parse(rawURL)
	if err != nil {
		return candidates
	}
	targetParsed, err := url.Parse(e.TargetURL)
	if err != nil {
		return candidates
	}
	if !sameURLAuthority(targetParsed, rawParsed) {
		return candidates
	}

	targetDirSegments := baseDirSegments(targetParsed.Path)
	rawSegments := splitPathSegments(rawParsed.Path)
	if len(targetDirSegments) == 0 || !hasSegmentPrefix(rawSegments, targetDirSegments) {
		return candidates
	}

	if e.BaseURL != "" {
		if baseParsed, err := url.Parse(e.BaseURL); err == nil && sameURLAuthority(baseParsed, rawParsed) {
			baseSegments := baseDirSegments(baseParsed.Path)
			if len(rawSegments) > len(targetDirSegments) {
				addURLCandidate(&candidates, rawParsed, appendSegments(baseSegments, rawSegments[len(targetDirSegments):]...))
			}
		}
	}

	tail := rawSegments[len(targetDirSegments):]
	for duplicateLen := min(len(targetDirSegments), len(tail)-1); duplicateLen > 0; duplicateLen-- {
		if !equalSegments(targetDirSegments[len(targetDirSegments)-duplicateLen:], tail[:duplicateLen]) {
			continue
		}
		repaired := appendSegments(targetDirSegments[:len(targetDirSegments)-duplicateLen], tail...)
		addURLCandidate(&candidates, rawParsed, repaired)
		break
	}

	return candidates
}

func sameURLAuthority(a, b *url.URL) bool {
	return strings.EqualFold(a.Scheme, b.Scheme) && strings.EqualFold(a.Host, b.Host)
}

func baseDirSegments(rawPath string) []string {
	if rawPath == "" || rawPath == "/" {
		return nil
	}
	basePath := rawPath
	if strings.HasSuffix(basePath, "/") {
		basePath = strings.TrimRight(basePath, "/")
	} else {
		basePath = path.Dir(basePath)
	}
	if basePath == "." || basePath == "/" {
		return nil
	}
	return splitPathSegments(basePath)
}

func splitPathSegments(rawPath string) []string {
	trimmed := strings.Trim(rawPath, "/")
	if trimmed == "" {
		return nil
	}
	parts := strings.Split(trimmed, "/")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func hasSegmentPrefix(values, prefix []string) bool {
	if len(values) < len(prefix) {
		return false
	}
	return equalSegments(values[:len(prefix)], prefix)
}

func equalSegments(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func appendSegments(base []string, tail ...string) []string {
	out := make([]string, 0, len(base)+len(tail))
	out = append(out, base...)
	out = append(out, tail...)
	return out
}

func addURLCandidate(candidates *[]string, template *url.URL, segments []string) {
	candidate := *template
	if len(segments) == 0 {
		candidate.Path = "/"
	} else {
		candidate.Path = "/" + strings.Join(segments, "/")
	}
	candidate.RawPath = ""
	value := candidate.String()
	for _, existing := range *candidates {
		if existing == value {
			return
		}
	}
	*candidates = append(*candidates, value)
}
