package enum

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/html"
	"golang.org/x/net/publicsuffix"

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

const maxNestedJSAssetDiscovery = 1000

var (
	quotedJSAssetPattern       = regexp.MustCompile(`["'\x60]([^"'\x60]+?\.(?:js|json|map)(?:\?[^"'\x60]*)?)["'\x60]`)
	webpackChunkMapPattern     = regexp.MustCompile(`["']([^"']*)["']\s*\+\s*[A-Za-z_$][A-Za-z0-9_$]*\s*\+\s*["']([^"']*)["']\s*\+\s*\{([^{}]+)\}\[[^\]]+\]\s*\+\s*["']([^"']*\.js)["']`)
	webpackChunkMapEntryRegexp = regexp.MustCompile(`(\d+):["']([A-Za-z0-9]+)["']`)
	webpackPublicPathPattern   = regexp.MustCompile(`\.p\s*=\s*["']([^"']*)["']`)
	sourceMappingURLPattern    = regexp.MustCompile(`(?m)(?://[#@]|/\*[#@])\s*sourceMappingURL=([^\s*]+)`)
)

// CrawlEnumerator crawls a target URL and enumerates discovered files for scanning.
// By default it filters for JavaScript and JSON files.
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
	NoSandbox          bool
	AutomaticFormFill  bool
	AuthCredentials    string
	UseInstalledChrome bool
	BrowserCapture     bool
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
	NoSandbox          bool
	AutomaticFormFill  bool
	AuthCredentials    string
	UseInstalledChrome bool
	BrowserCapture     bool
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
		cfg.Extensions = []string{"js", "json", "map"}
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
		NoSandbox:          cfg.NoSandbox,
		AutomaticFormFill:  cfg.AutomaticFormFill,
		AuthCredentials:    cfg.AuthCredentials,
		UseInstalledChrome: cfg.UseInstalledChrome,
		BrowserCapture:     cfg.BrowserCapture,
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
// The crawl engine is used for URL discovery. LeakLens also extracts first-page
// HTML assets directly so Rails importmaps, modulepreload links, and Link header
// preload targets are not missed when the crawl engine does not emit them.
// Actual content download is handled separately by URLEnumerator.
func (e *CrawlEnumerator) Enumerate(ctx context.Context, callback func(content []byte, blobID types.BlobID, prov types.Provenance) error) error {
	var mu sync.Mutex
	seen := make(map[string]struct{})
	var discoveredURLs []string
	var discoveredCandidates [][]string
	var acceptingResults atomic.Bool
	acceptingResults.Store(true)

	addDiscoveredURL := func(rawURL string) {
		if rawURL == "" {
			return
		}
		rawURL = normalizeDiscoveredAssetURL(rawURL)
		if !e.urlInScope(rawURL) {
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
		if _, dup := seen[key]; dup {
			return
		}
		seen[key] = struct{}{}
		discoveredURLs = append(discoveredURLs, rawURL)
		discoveredCandidates = append(discoveredCandidates, candidates)
		warnf("  found: %s\n", rawURL)
	}

	crawlRequestTimeout := 30
	if e.Timeout > 0 && e.Timeout < time.Duration(crawlRequestTimeout)*time.Second {
		crawlRequestTimeout = max(1, int(math.Ceil(e.Timeout.Seconds())))
	}

	// Do NOT set ExtensionsMatch here: the crawl engine uses it to filter which
	// URLs to visit (not just which to report), so setting it to ["js"] would
	// prevent HTML page visits and it would never discover JS links.
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
		HeadlessNoSandbox:   e.headlessNoSandbox(),
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
			addDiscoveredURL(rawURL)
		},
	}

	if e.Timeout > 0 {
		options.CrawlDuration = e.Timeout
	}
	if e.Headless {
		options.Headless = true
		if options.HeadlessNoSandbox && !e.NoSandbox {
			warnf("warning: running as root; enabling Chrome --no-sandbox for headless crawl\n")
		}
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
				warnf("Crawl cleanup warning: %v\n", err)
			}
		})
	}
	defer closeEngine()

	mode := "standard"
	if e.Headless {
		mode = "headless"
	}
	warnf("Crawling %s (%s, depth=%d, extensions=%s)...\n",
		e.TargetURL, mode, e.MaxDepth, strings.Join(e.Extensions, ","))

	var runtimeBlobs []browserCaptureBlob
	if e.BrowserCapture {
		result, err := runBrowserRuntimeCapture(ctx, e)
		if err != nil {
			warnf("warning: browser runtime capture unavailable; continuing with standard crawl only: %v\n", err)
		} else {
			for _, rawURL := range result.URLs {
				addDiscoveredURL(rawURL)
			}
			runtimeBlobs = append(runtimeBlobs, result.Blobs...)
			if len(result.Blobs) > 0 {
				warnf("  runtime: captured %d browser observation blob(s)\n", len(result.Blobs))
			}
		}
	}

	initialURLs, initialErr := e.discoverInitialAssetURLs(ctx)
	if initialErr != nil {
		warnf("warning: initial HTML asset discovery failed: %v\n", initialErr)
	} else {
		for _, rawURL := range initialURLs {
			addDiscoveredURL(rawURL)
		}
	}
	for _, rawURL := range e.discoverAssetManifestURLs(ctx) {
		addDiscoveredURL(rawURL)
	}

	err, timedOut := e.runCrawlWithDeadline(ctx, engine, closeEngine)

	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if timedOut {
			acceptingResults.Store(false)
			warnf("Crawl stopped: timeout %s reached\n", e.Timeout)
		} else {
			// Crawl timeout or other non-fatal crawl errors: log and continue
			// with whatever URLs were discovered before the error.
			warnf("Crawl stopped: %v\n", err)
		}
	} else if timedOut {
		// Crawl timeout or other non-fatal crawl errors: log and continue
		// with whatever URLs were discovered before the error.
		acceptingResults.Store(false)
		warnf("Crawl stopped: timeout %s reached\n", e.Timeout)
	}

	if shouldRunPostCrawlDiscovery(ctx, timedOut, e.JSCrawl) {
		mu.Lock()
		seedURLs := append([]string(nil), discoveredURLs...)
		mu.Unlock()
		for _, rawURL := range e.discoverNestedJSAssetURLs(ctx, seedURLs) {
			addDiscoveredURL(rawURL)
		}
	}
	if shouldRunPostCrawlDiscovery(ctx, timedOut, extensionEnabled(e.Extensions, "map")) {
		mu.Lock()
		seedURLs := append([]string(nil), discoveredURLs...)
		mu.Unlock()
		for _, rawURL := range e.discoverSourceMapAssetURLs(ctx, seedURLs) {
			addDiscoveredURL(rawURL)
		}
	}

	mu.Lock()
	acceptingResults.Store(false)
	finalURLs := append([]string(nil), discoveredURLs...)
	finalCandidates := append([][]string(nil), discoveredCandidates...)
	mu.Unlock()

	if len(finalURLs) == 0 && len(runtimeBlobs) == 0 {
		warnf("Crawl complete: no matching files found\n")
		return nil
	}

	warnf("Crawl complete: discovered %d unique %s file(s), downloading and scanning...\n",
		len(finalURLs), strings.Join(e.Extensions, "/"))

	downloadedBlobIDs := make(map[types.BlobID]struct{})
	var urlErr error
	if len(finalCandidates) > 0 {
		urlEnum := NewURLEnumeratorWithCandidates(finalCandidates, e.MaxSize)
		urlErr = urlEnum.Enumerate(ctx, func(content []byte, blobID types.BlobID, prov types.Provenance) error {
			mu.Lock()
			downloadedBlobIDs[blobID] = struct{}{}
			mu.Unlock()
			return callback(content, blobID, prov)
		})
		if urlErr != nil && !errors.Is(urlErr, errAllURLFetchesFailed) {
			return urlErr
		}
	}

	runtimeBlobIDs := make(map[types.BlobID]struct{})
	runtimeEmitted := 0
	for _, blob := range runtimeBlobs {
		content := append([]byte(nil), blob.Content...)
		if len(content) == 0 || (e.MaxSize > 0 && int64(len(content)) > e.MaxSize) {
			continue
		}
		blobID := types.ComputeBlobID(content)
		if _, ok := downloadedBlobIDs[blobID]; ok {
			continue
		}
		if _, ok := runtimeBlobIDs[blobID]; ok {
			continue
		}
		runtimeBlobIDs[blobID] = struct{}{}
		if err := callback(content, blobID, blob.Provenance); err != nil {
			return err
		}
		runtimeEmitted++
	}

	if urlErr != nil {
		if runtimeEmitted == 0 {
			return urlErr
		}
		warnf("warning: standard asset downloads failed; scanned %d unique browser-captured blob(s) instead\n", runtimeEmitted)
	}
	return nil
}

func shouldRunPostCrawlDiscovery(ctx context.Context, timedOut bool, enabled bool) bool {
	if !enabled || timedOut {
		return false
	}
	return ctx.Err() == nil
}

func (e *CrawlEnumerator) discoverInitialAssetURLs(ctx context.Context) ([]string, error) {
	timeout := 30 * time.Second
	if e.Timeout > 0 && e.Timeout < timeout {
		timeout = e.Timeout
	}

	client := newTLSFallbackHTTPClient(timeout)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, e.TargetURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "text/html,application/xhtml+xml")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return e.filterInScope(extractHeaderAssetURLs(resp.Request.URL, resp.Header, e.Extensions)), nil
	}

	reader := io.LimitReader(resp.Body, e.MaxSize+1)
	body, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > e.MaxSize {
		return e.filterInScope(extractHeaderAssetURLs(resp.Request.URL, resp.Header, e.Extensions)), nil
	}

	return e.filterInScope(extractHTMLAssetURLs(resp.Request.URL, resp.Header, body, e.Extensions)), nil
}

func (e *CrawlEnumerator) filterInScope(urls []string) []string {
	out := make([]string, 0, len(urls))
	for _, rawURL := range urls {
		if e.urlInScope(rawURL) {
			out = append(out, rawURL)
		}
	}
	return out
}

func (e *CrawlEnumerator) discoverAssetManifestURLs(ctx context.Context) []string {
	base, err := url.Parse(e.TargetURL)
	if err != nil || base.Scheme == "" || base.Host == "" {
		return nil
	}
	manifest := *base
	manifest.Path = "/asset-manifest.json"
	manifest.RawQuery = ""
	manifest.Fragment = ""

	timeout := 30 * time.Second
	if e.Timeout > 0 && e.Timeout < timeout {
		timeout = e.Timeout
	}
	client := newTLSFallbackHTTPClient(timeout)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, manifest.String(), nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Accept", "application/json,*/*")

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil
	}
	contentType := strings.ToLower(resp.Header.Get("Content-Type"))
	if strings.Contains(contentType, "text/html") {
		return nil
	}

	reader := io.LimitReader(resp.Body, e.MaxSize+1)
	body, err := io.ReadAll(reader)
	if err != nil || int64(len(body)) > e.MaxSize {
		return nil
	}
	if !json.Valid(body) {
		return nil
	}

	urls := []string{manifest.String()}
	urls = append(urls, extractAssetManifestURLs(&manifest, body, e.Extensions)...)
	return e.filterInScope(uniqueStrings(urls))
}

func extractHTMLAssetURLs(base *url.URL, headers http.Header, body []byte, extensions []string) []string {
	urls := extractHeaderAssetURLs(base, headers, extensions)

	root, err := html.Parse(strings.NewReader(string(body)))
	if err != nil {
		return uniqueStrings(urls)
	}

	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode {
			switch strings.ToLower(n.Data) {
			case "script":
				scriptType := strings.ToLower(strings.TrimSpace(nodeAttr(n, "type")))
				if src := nodeAttr(n, "src"); src != "" {
					addResolvedAssetURL(&urls, base, src, extensions)
				}
				if scriptType == "importmap" {
					urls = append(urls, extractImportMapAssetURLs(base, nodeText(n), extensions)...)
				}
			case "link":
				rel := nodeAttr(n, "rel")
				as := nodeAttr(n, "as")
				if shouldCollectLinkAsset(rel, as) {
					if href := nodeAttr(n, "href"); href != "" {
						addResolvedAssetURL(&urls, base, href, extensions)
					}
				}
			}
		}
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(root)

	return uniqueStrings(urls)
}

func extractHeaderAssetURLs(base *url.URL, headers http.Header, extensions []string) []string {
	var urls []string
	for _, header := range headers.Values("Link") {
		for _, part := range splitHTTPLinkHeader(header) {
			start := strings.Index(part, "<")
			end := strings.Index(part, ">")
			if start < 0 || end <= start {
				continue
			}
			addResolvedAssetURL(&urls, base, part[start+1:end], extensions)
		}
	}
	return uniqueStrings(urls)
}

func extractImportMapAssetURLs(base *url.URL, data string, extensions []string) []string {
	var parsed struct {
		Imports map[string]string            `json:"imports"`
		Scopes  map[string]map[string]string `json:"scopes"`
	}
	if err := json.Unmarshal([]byte(data), &parsed); err != nil {
		return nil
	}

	var urls []string
	for _, value := range parsed.Imports {
		addResolvedAssetURL(&urls, base, value, extensions)
	}
	for _, imports := range parsed.Scopes {
		for _, value := range imports {
			addResolvedAssetURL(&urls, base, value, extensions)
		}
	}
	return uniqueStrings(urls)
}

func (e *CrawlEnumerator) discoverNestedJSAssetURLs(ctx context.Context, seedURLs []string) []string {
	if len(seedURLs) == 0 {
		return nil
	}
	timeout := 30 * time.Second
	if e.Timeout > 0 && e.Timeout < timeout {
		timeout = e.Timeout
	}
	client := newTLSFallbackHTTPClient(timeout)
	queued := make(map[string]bool)
	seenAsset := make(map[string]bool)
	queue := make([]string, 0, len(seedURLs))
	for _, rawURL := range seedURLs {
		seenAsset[rawURL] = true
		if isJavaScriptURL(rawURL) {
			queued[rawURL] = true
			queue = append(queue, rawURL)
		}
	}

	var discovered []string
	for len(queue) > 0 && len(discovered) < maxNestedJSAssetDiscovery {
		if ctx.Err() != nil {
			return discovered
		}
		current := queue[0]
		queue = queue[1:]
		body, responseURL, err := fetchJSAssetForDiscovery(ctx, client, current, e.MaxSize)
		if err != nil {
			continue
		}
		for _, rawURL := range extractJSAssetURLs(responseURL, body, e.Extensions) {
			if len(discovered) >= maxNestedJSAssetDiscovery {
				break
			}
			if !e.urlInScope(rawURL) || !urlMatchesExtensions(rawURL, e.Extensions) {
				continue
			}
			if seenAsset[rawURL] {
				continue
			}
			seenAsset[rawURL] = true
			discovered = append(discovered, rawURL)
			if isJavaScriptURL(rawURL) && !queued[rawURL] {
				queued[rawURL] = true
				queue = append(queue, rawURL)
			}
		}
	}
	return discovered
}

func (e *CrawlEnumerator) discoverSourceMapAssetURLs(ctx context.Context, seedURLs []string) []string {
	if len(seedURLs) == 0 {
		return nil
	}
	timeout := 30 * time.Second
	if e.Timeout > 0 && e.Timeout < timeout {
		timeout = e.Timeout
	}
	client := newTLSFallbackHTTPClient(timeout)
	seen := make(map[string]struct{})
	var discovered []string
	for _, rawURL := range seedURLs {
		if ctx.Err() != nil {
			return discovered
		}
		if !isJavaScriptURL(rawURL) {
			continue
		}
		for _, candidate := range sourceMapURLCandidates(rawURL) {
			candidate = normalizeDiscoveredAssetURL(candidate)
			if !e.urlInScope(candidate) || !urlMatchesExtensions(candidate, e.Extensions) {
				continue
			}
			if _, ok := seen[candidate]; ok {
				continue
			}
			seen[candidate] = struct{}{}
			if sourceMapURLExists(ctx, client, candidate) {
				discovered = append(discovered, candidate)
			}
		}
	}
	return discovered
}

func fetchJSAssetForDiscovery(ctx context.Context, client *http.Client, rawURL string, maxSize int64) ([]byte, *url.URL, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Accept", "application/javascript,text/javascript,*/*")
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	reader := io.LimitReader(resp.Body, maxSize+1)
	body, err := io.ReadAll(reader)
	if err != nil {
		return nil, nil, err
	}
	if int64(len(body)) > maxSize {
		return nil, nil, fmt.Errorf("JS asset too large")
	}
	return body, resp.Request.URL, nil
}

func extractAssetManifestURLs(base *url.URL, body []byte, extensions []string) []string {
	var decoded interface{}
	if err := json.Unmarshal(body, &decoded); err != nil {
		return nil
	}

	var urls []string
	var walk func(interface{})
	walk = func(value interface{}) {
		switch typed := value.(type) {
		case string:
			addResolvedAssetURL(&urls, base, typed, extensions)
		case []interface{}:
			for _, item := range typed {
				walk(item)
			}
		case map[string]interface{}:
			for key, item := range typed {
				if strings.Contains(key, "/") || strings.HasPrefix(key, ".") || hasURLScheme(key) {
					addResolvedAssetURL(&urls, base, key, extensions)
				}
				walk(item)
			}
		}
	}
	walk(decoded)
	return uniqueStrings(urls)
}

func extractJSAssetURLs(base *url.URL, body []byte, extensions []string) []string {
	var urls []string
	text := string(body)
	publicPath := extractWebpackPublicPath(text)
	for _, match := range sourceMappingURLPattern.FindAllStringSubmatch(text, -1) {
		if len(match) > 1 {
			addResolvedJSAssetURL(&urls, base, publicPath, match[1], extensions)
		}
	}
	for _, match := range quotedJSAssetPattern.FindAllStringSubmatch(text, -1) {
		if len(match) > 1 {
			addResolvedJSAssetURL(&urls, base, publicPath, match[1], extensions)
		}
	}
	for _, match := range webpackChunkMapPattern.FindAllStringSubmatch(text, -1) {
		if len(match) < 5 {
			continue
		}
		prefix, separator, entries, suffix := match[1], match[2], match[3], match[4]
		for _, entry := range webpackChunkMapEntryRegexp.FindAllStringSubmatch(entries, -1) {
			if len(entry) < 3 {
				continue
			}
			addResolvedJSAssetURL(&urls, base, publicPath, prefix+entry[1]+separator+entry[2]+suffix, extensions)
		}
	}
	return uniqueStrings(urls)
}

func extractWebpackPublicPath(text string) string {
	matches := webpackPublicPathPattern.FindAllStringSubmatch(text, -1)
	if len(matches) == 0 || len(matches[len(matches)-1]) < 2 {
		return ""
	}
	return matches[len(matches)-1][1]
}

func addResolvedJSAssetURL(out *[]string, base *url.URL, publicPath, raw string, extensions []string) {
	var ok bool
	raw, ok = normalizeJSAssetLiteral(base, raw)
	if !ok {
		return
	}
	if strings.HasPrefix(raw, "/") || hasURLScheme(raw) {
		addResolvedAssetURL(out, base, raw, extensions)
		return
	}
	if strings.TrimSpace(publicPath) != "" {
		addResolvedAssetURL(out, base, joinPublicPath(publicPath, raw), extensions)
		if strings.HasPrefix(raw, "static/") {
			addResolvedAssetURL(out, base, "/"+raw, extensions)
		}
		return
	}
	if repaired, ok := repairDuplicatedRelativeAssetDir(base, raw); ok {
		addResolvedAssetURL(out, base, repaired, extensions)
		return
	}
	addResolvedAssetURL(out, base, raw, extensions)
	if !strings.HasPrefix(raw, "/") && strings.HasPrefix(raw, "static/") {
		addResolvedAssetURL(out, base, "/"+raw, extensions)
	}
}

func normalizeJSAssetLiteral(base *url.URL, raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.ContainsAny(raw, " \t\r\n") {
		return "", false
	}
	raw = strings.NewReplacer(`\/`, `/`, `\u002f`, `/`, `\u002F`, `/`).Replace(raw)
	if strings.Contains(raw, "${") || strings.ContainsAny(raw, "{}") {
		return "", false
	}
	if strings.Contains(raw, `\`) {
		if !strings.HasPrefix(raw, `\`) && !strings.HasPrefix(raw, "/") {
			return "", false
		}
		host := ""
		if base != nil {
			host = base.Hostname()
		}
		raw = cleanBackslashAssetPath(raw, host)
	}
	if raw == "" || (strings.HasPrefix(raw, ".") && !strings.HasPrefix(raw, "./") && !strings.HasPrefix(raw, "../")) {
		return "", false
	}
	return raw, true
}

func repairDuplicatedRelativeAssetDir(base *url.URL, raw string) (string, bool) {
	if base == nil || strings.HasPrefix(raw, ".") {
		return "", false
	}
	rawSegments := splitPathSegments(raw)
	baseSegments := baseDirSegments(base.Path)
	if len(rawSegments) == 0 || len(baseSegments) == 0 {
		return "", false
	}
	if rawSegments[0] != baseSegments[len(baseSegments)-1] {
		return "", false
	}
	repairedSegments := appendSegments(baseSegments[:len(baseSegments)-1], rawSegments...)
	return "/" + strings.Join(repairedSegments, "/"), true
}

func normalizeDiscoveredAssetURL(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return rawURL
	}
	decodedPath, err := url.PathUnescape(parsed.EscapedPath())
	if err != nil {
		decodedPath = parsed.Path
	}
	if !strings.Contains(decodedPath, `\`) {
		return rawURL
	}
	parsed.Path = cleanBackslashAssetPath(decodedPath, parsed.Hostname())
	parsed.RawPath = ""
	if (parsed.Scheme == "https" && parsed.Port() == "443") || (parsed.Scheme == "http" && parsed.Port() == "80") {
		hostname := parsed.Hostname()
		if !strings.Contains(hostname, ":") {
			parsed.Host = hostname
		}
	}
	return parsed.String()
}

func cleanBackslashAssetPath(raw, host string) string {
	cleaned := strings.ReplaceAll(raw, `\`, "")
	cleaned = collapseSlashes(cleaned)
	if host != "" {
		cleaned = dropLeadingHostPathSegment(cleaned, host)
	}
	return cleaned
}

func dropLeadingHostPathSegment(rawPath, host string) string {
	segments := splitPathSegments(rawPath)
	if len(segments) == 0 || !strings.EqualFold(segments[0], host) {
		return rawPath
	}
	if len(segments) == 1 {
		return "/"
	}
	return "/" + strings.Join(segments[1:], "/")
}

func collapseSlashes(value string) string {
	var b strings.Builder
	b.Grow(len(value))
	previousSlash := false
	for _, r := range value {
		if r == '/' {
			if !previousSlash {
				b.WriteRune(r)
			}
			previousSlash = true
			continue
		}
		previousSlash = false
		b.WriteRune(r)
	}
	return b.String()
}

func hasURLScheme(raw string) bool {
	parsed, err := url.Parse(raw)
	return err == nil && parsed.Scheme != ""
}

func joinPublicPath(publicPath, raw string) string {
	if publicPath == "" {
		return raw
	}
	if strings.HasSuffix(publicPath, "/") {
		return publicPath + strings.TrimLeft(raw, "/")
	}
	return publicPath + "/" + strings.TrimLeft(raw, "/")
}

func isJavaScriptURL(rawURL string) bool {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	switch strings.ToLower(path.Ext(parsed.Path)) {
	case ".js", ".mjs", ".cjs":
		return true
	default:
		return false
	}
}

func sourceMapURLCandidates(rawURL string) []string {
	if !isJavaScriptURL(rawURL) {
		return nil
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return nil
	}
	parsed.Fragment = ""
	originalQuery := parsed.RawQuery
	parsed.RawQuery = ""
	parsed.Path += ".map"
	candidates := []string{parsed.String()}
	if originalQuery != "" {
		parsed.RawQuery = originalQuery
		candidates = append(candidates, parsed.String())
	}
	return uniqueStrings(candidates)
}

func sourceMapURLExists(ctx context.Context, client *http.Client, rawURL string) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, rawURL, nil)
	if err != nil {
		return false
	}
	req.Header.Set("Accept", "application/json,application/source-map,*/*")
	resp, err := client.Do(req)
	if err == nil {
		resp.Body.Close()
		if sourceMapResponseOK(resp) {
			return true
		}
		if resp.StatusCode != http.StatusMethodNotAllowed && resp.StatusCode != http.StatusForbidden {
			return false
		}
	}

	req, err = http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return false
	}
	req.Header.Set("Accept", "application/json,application/source-map,*/*")
	req.Header.Set("Range", "bytes=0-0")
	resp, err = client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	_, _ = io.CopyN(io.Discard, resp.Body, 1)
	return sourceMapResponseOK(resp)
}

func sourceMapResponseOK(resp *http.Response) bool {
	if resp == nil || resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return false
	}
	contentType := strings.ToLower(resp.Header.Get("Content-Type"))
	return !strings.Contains(contentType, "text/html")
}

func extensionEnabled(extensions []string, ext string) bool {
	ext = strings.TrimPrefix(strings.ToLower(ext), ".")
	for _, value := range extensions {
		if strings.TrimPrefix(strings.ToLower(value), ".") == ext {
			return true
		}
	}
	return false
}

func addResolvedAssetURL(out *[]string, base *url.URL, raw string, extensions []string) {
	resolved, ok := resolveAssetURL(base, raw)
	if !ok {
		return
	}
	if !urlMatchesExtensions(resolved, extensions) {
		return
	}
	*out = append(*out, resolved)
}

func resolveAssetURL(base *url.URL, raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.HasPrefix(raw, "#") {
		return "", false
	}

	parsed, err := url.Parse(raw)
	if err != nil {
		return "", false
	}
	if parsed.Scheme != "" && parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", false
	}
	if base != nil {
		parsed = base.ResolveReference(parsed)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", false
	}
	parsed.Fragment = ""
	return parsed.String(), true
}

func shouldCollectLinkAsset(rel, as string) bool {
	relValues := strings.Fields(strings.ToLower(rel))
	as = strings.ToLower(strings.TrimSpace(as))
	for _, value := range relValues {
		switch value {
		case "modulepreload", "preload", "prefetch", "stylesheet":
			return as == "" || as == "script" || as == "fetch" || as == "style"
		}
	}
	return false
}

func nodeAttr(n *html.Node, key string) string {
	for _, attr := range n.Attr {
		if strings.EqualFold(attr.Key, key) {
			return attr.Val
		}
	}
	return ""
}

func nodeText(n *html.Node) string {
	var b strings.Builder
	var walk func(*html.Node)
	walk = func(node *html.Node) {
		if node.Type == html.TextNode {
			b.WriteString(node.Data)
		}
		for child := node.FirstChild; child != nil; child = child.NextSibling {
			walk(child)
		}
	}
	walk(n)
	return b.String()
}

func splitHTTPLinkHeader(header string) []string {
	var parts []string
	start := 0
	inQuote := false
	for i, r := range header {
		switch r {
		case '"':
			inQuote = !inQuote
		case ',':
			if !inQuote {
				parts = append(parts, strings.TrimSpace(header[start:i]))
				start = i + 1
			}
		}
	}
	parts = append(parts, strings.TrimSpace(header[start:]))
	return parts
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
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

func (e *CrawlEnumerator) headlessNoSandbox() bool {
	return shouldUseHeadlessNoSandboxForEUID(e.NoSandbox, e.Headless, e.ChromeWSURL, currentEUID())
}

func shouldUseHeadlessNoSandboxForEUID(explicit, headless bool, chromeWSURL string, euid int) bool {
	if explicit {
		return true
	}
	return headless && chromeWSURL == "" && euid == 0
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

func (e *CrawlEnumerator) urlInScope(rawURL string) bool {
	targetParsed, err := url.Parse(e.TargetURL)
	if err != nil {
		return true
	}
	rawParsed, err := url.Parse(rawURL)
	if err != nil {
		return false
	}

	switch strings.ToLower(e.Scope) {
	case "rdn":
		targetDomain, targetErr := publicsuffix.EffectiveTLDPlusOne(targetParsed.Hostname())
		rawDomain, rawErr := publicsuffix.EffectiveTLDPlusOne(rawParsed.Hostname())
		if targetErr == nil && rawErr == nil {
			return strings.EqualFold(targetDomain, rawDomain)
		}
		return strings.EqualFold(targetParsed.Host, rawParsed.Host)
	case "dn", "fqdn":
		return strings.EqualFold(targetParsed.Host, rawParsed.Host)
	default:
		return sameURLAuthority(targetParsed, rawParsed)
	}
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
