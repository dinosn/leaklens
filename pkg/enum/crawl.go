package enum

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"path"
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
		NoSandbox:          cfg.NoSandbox,
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

	initialURLs, initialErr := e.discoverInitialAssetURLs(ctx)
	if initialErr != nil {
		warnf("warning: initial HTML asset discovery failed: %v\n", initialErr)
	} else {
		for _, rawURL := range initialURLs {
			addDiscoveredURL(rawURL)
		}
	}

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
			warnf("Crawl stopped: timeout %s reached\n", e.Timeout)
		} else {
			// Crawl timeout or other non-fatal crawl errors: log and continue
			// with whatever URLs were discovered before the error.
			warnf("Crawl stopped: %v\n", err)
		}
	} else if timedOut {
		// Crawl timeout or other non-fatal crawl errors: log and continue
		// with whatever URLs were discovered before the error.
		warnf("Crawl stopped: timeout %s reached\n", e.Timeout)
	}

	if len(finalURLs) == 0 {
		warnf("Crawl complete: no matching files found\n")
		return nil
	}

	warnf("Crawl complete: discovered %d unique %s file(s), downloading and scanning...\n",
		len(finalURLs), strings.Join(e.Extensions, "/"))

	urlEnum := NewURLEnumeratorWithCandidates(finalCandidates, e.MaxSize)
	return urlEnum.Enumerate(ctx, callback)
}

func (e *CrawlEnumerator) discoverInitialAssetURLs(ctx context.Context) ([]string, error) {
	timeout := 30 * time.Second
	if e.Timeout > 0 && e.Timeout < timeout {
		timeout = e.Timeout
	}

	client := &http.Client{Timeout: timeout}
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
