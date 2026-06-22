package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dinosn/leaklens/pkg/datastore"
	"github.com/dinosn/leaklens/pkg/enum"
	"github.com/dinosn/leaklens/pkg/jsintel"
	"github.com/dinosn/leaklens/pkg/matcher"
	"github.com/dinosn/leaklens/pkg/rule"
	"github.com/dinosn/leaklens/pkg/sarif"
	"github.com/dinosn/leaklens/pkg/store"
	"github.com/dinosn/leaklens/pkg/types"
	"github.com/dinosn/leaklens/pkg/validator"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"
	"golang.org/x/term"
)

// extensionsValue is a custom flag type that displays as "extensions" in help
type extensionsValue string

const (
	defaultCrawlDepth       = 3
	defaultCrawlConcurrency = 2
	defaultCrawlRateLimit   = 3
	defaultCrawlTimeout     = "2m"
	defaultCrawlExtensions  = "js,json"
	defaultCrawlScope       = "rdn"
)

func (e *extensionsValue) String() string {
	return string(*e)
}

func (e *extensionsValue) Set(val string) error {
	*e = extensionsValue(val)
	return nil
}

func (e *extensionsValue) Type() string {
	return "extensions"
}

var (
	scanRulesPath            string
	scanRulesInclude         string
	scanRulesExclude         string
	scanOutputPath           string
	scanOutputFormat         string
	scanGit                  bool
	scanMaxFileSize          int64
	scanIncludeHidden        bool
	scanContextLines         int
	scanIncremental          bool
	scanValidate             bool
	scanValidateWorkers      int
	scanStoreBlobs           bool
	scanExtractArchivesFlag  extensionsValue
	extractMaxSize           string
	extractMaxTotal          string
	extractMaxDepth          int
	scanSQLiteRowLimit       int
	scanWorkers              int
	scanURLFile              string
	scanCrawl                bool
	scanCrawlDepth           int
	scanCrawlConcurrency     int
	scanCrawlRateLimit       int
	scanCrawlHostRateLimit   int
	scanCrawlTimeout         string
	scanCrawlHeadless        bool
	scanCrawlJSCrawl         bool
	scanCrawlExtensions      string
	scanCrawlScope           string
	scanCrawlBaseURL         string
	scanCrawlMaxDomainPages  int
	scanCrawlChromeDataDir   string
	scanCrawlChromeWSURL     string
	scanCrawlSystemChrome    string
	scanCrawlNoIncognito     bool
	scanCrawlNoSandbox       bool
	scanCrawlAutoFormFill    bool
	scanCrawlAuth            string
	scanCrawlInstalledChrome bool
	scanJSIntel              bool
	scanJSIntelSourceMaps    bool
	scanJSIntelGeneric       bool
	scanJSIntelNPMCheck      bool
)

var scanCmd = &cobra.Command{
	Use:   "scan [target]",
	Short: "Scan a target for secrets",
	Long: `Scan a file, directory, git repository, HTTP(S) URL, or remote GitHub/GitLab repository for secrets using detection rules.
Supports github.com/org/repo and gitlab.com/namespace/project URLs for direct remote scanning.
HTTP(S) URLs are downloaded and scanned directly. Use --url-file to scan a list of URLs from a file (use - for stdin).
Use --crawl with a URL target to spider the site and scan discovered files (JS and JSON by default).`,
	Args: cobra.RangeArgs(0, 1),
	RunE: runScan,
}

func init() {
	scanCmd.Flags().StringVar(&scanRulesPath, "rules", "", "Path to custom rules file or directory")
	scanCmd.Flags().StringVar(&scanRulesInclude, "rules-include", "", "Include rules matching regex pattern (comma-separated)")
	scanCmd.Flags().StringVar(&scanRulesExclude, "rules-exclude", "", "Exclude rules matching regex pattern (comma-separated)")
	scanCmd.Flags().StringVar(&scanOutputPath, "output", "leaklens.ds", "Output datastore path (use :memory: for in-memory only)")
	scanCmd.Flags().StringVar(&scanOutputFormat, "format", "human", "Output format: json, sarif, human")
	scanCmd.Flags().BoolVar(&scanGit, "git", false, "Treat target as git repository (enumerate git history)")
	scanCmd.Flags().Int64Var(&scanMaxFileSize, "max-file-size", 10*1024*1024, "Maximum file size to scan (bytes)")
	scanCmd.Flags().BoolVar(&scanIncludeHidden, "include-hidden", false, "Include hidden files and directories")
	scanCmd.Flags().IntVar(&scanContextLines, "context-lines", 3, "Lines of context before/after matches (0 to disable)")
	scanCmd.Flags().BoolVar(&scanIncremental, "incremental", false, "Skip already-scanned blobs")
	scanCmd.Flags().BoolVar(&scanValidate, "validate", false, "validate detected secrets against their source APIs")
	scanCmd.Flags().IntVar(&scanValidateWorkers, "validate-workers", 4, "number of concurrent validation workers")
	scanCmd.Flags().BoolVar(&scanStoreBlobs, "store-blobs", false, "Store file contents in blobs/ directory")
	scanCmd.Flags().Var(&scanExtractArchivesFlag, "extract", "Extract text from binary files (extensions: xlsx,docx,pdf,zip or 'all')")
	scanCmd.Flags().StringVar(&extractMaxSize, "extract-max-size", "10MB", "Max uncompressed size per extracted file")
	scanCmd.Flags().StringVar(&extractMaxTotal, "extract-max-total", "100MB", "Max total bytes to extract from one archive")
	scanCmd.Flags().IntVar(&extractMaxDepth, "extract-max-depth", 5, "Max nested archive depth")
	scanCmd.Flags().IntVar(&scanSQLiteRowLimit, "sqlite-row-limit", 1000, "Max rows per table for SQLite extraction (0 for unlimited)")
	scanCmd.Flags().IntVar(&scanWorkers, "workers", runtime.NumCPU(), "Number of parallel scan workers")
	scanCmd.Flags().StringVar(&scanURLFile, "url-file", "", "File containing URLs to scan, one per line (use - for stdin)")

	scanCmd.Flags().BoolVar(&scanCrawl, "crawl", false, "Crawl the target URL to discover files for scanning")
	scanCmd.Flags().IntVar(&scanCrawlDepth, "crawl-depth", defaultCrawlDepth, "Maximum crawl depth")
	scanCmd.Flags().IntVar(&scanCrawlConcurrency, "crawl-concurrency", defaultCrawlConcurrency, "Number of concurrent crawl workers")
	scanCmd.Flags().IntVar(&scanCrawlRateLimit, "crawl-rate-limit", defaultCrawlRateLimit, "Maximum crawl requests per second")
	scanCmd.Flags().IntVar(&scanCrawlHostRateLimit, "crawl-host-rate-limit", 0, "Maximum crawl requests per second per host (0 uses --crawl-rate-limit)")
	scanCmd.Flags().StringVar(&scanCrawlTimeout, "crawl-timeout", defaultCrawlTimeout, "Maximum crawl duration (e.g. 5m, 30s)")
	scanCmd.Flags().BoolVar(&scanCrawlHeadless, "crawl-headless", false, "Use headless browser for crawling (discovers dynamically loaded scripts)")
	scanCmd.Flags().BoolVar(&scanCrawlJSCrawl, "crawl-js-crawl", true, "Parse JavaScript files for additional endpoints during crawl")
	scanCmd.Flags().StringVar(&scanCrawlExtensions, "crawl-extensions", defaultCrawlExtensions, "File extensions to match during crawl (comma-separated)")
	scanCmd.Flags().StringVar(&scanCrawlScope, "crawl-scope", defaultCrawlScope, "Crawl scope: rdn (registered domain), dn (domain name), fqdn (exact hostname)")
	scanCmd.Flags().StringVar(&scanCrawlBaseURL, "crawl-base-url", "", "Application base URL for repairing JS-discovered relative paths")
	scanCmd.Flags().IntVar(&scanCrawlMaxDomainPages, "crawl-max-domain-pages", 0, "Maximum pages to crawl per domain (0 = unlimited)")
	scanCmd.Flags().StringVar(&scanCrawlChromeDataDir, "crawl-chrome-data-dir", "", "Chrome user-data-dir to preserve crawl sessions")
	scanCmd.Flags().StringVar(&scanCrawlChromeWSURL, "crawl-chrome-ws-url", "", "Chrome DevTools websocket URL to attach to an existing browser")
	scanCmd.Flags().StringVar(&scanCrawlSystemChrome, "crawl-system-chrome-path", "", "Chrome/Chromium binary path for headless crawling")
	scanCmd.Flags().BoolVar(&scanCrawlInstalledChrome, "crawl-use-installed-chrome", false, "Use installed Chrome instead of Katana-managed Chrome")
	scanCmd.Flags().BoolVar(&scanCrawlNoIncognito, "crawl-no-incognito", false, "Run headless crawl without an incognito context")
	scanCmd.Flags().BoolVar(&scanCrawlNoSandbox, "crawl-no-sandbox", false, "Run headless Chrome with --no-sandbox (auto-enabled when running as root)")
	scanCmd.Flags().BoolVar(&scanCrawlAutoFormFill, "crawl-automatic-form-fill", false, "Enable Katana automatic form filling and submission")
	scanCmd.Flags().StringVar(&scanCrawlAuth, "crawl-auth", "", "username:password for Katana automatic login")

	scanCmd.Flags().BoolVar(&scanJSIntel, "js-intel", false, "Extract JS intelligence artifacts and rescan inline source-map sources")
	scanCmd.Flags().BoolVar(&scanJSIntelSourceMaps, "js-intel-source-maps", true, "When --js-intel is enabled, parse inline source maps and scan embedded sources")
	scanCmd.Flags().BoolVar(&scanJSIntelGeneric, "js-intel-generic-secrets", false, "Enable low-confidence JS-style generic secret heuristics")
	scanCmd.Flags().BoolVar(&scanJSIntelNPMCheck, "js-intel-npm-check", false, "Actively check discovered npm packages for public-registry misses")
}

// blobJob represents a unit of work for the worker pool.
type blobJob struct {
	content []byte
	blobID  types.BlobID
	prov    types.Provenance
}

func runScan(cmd *cobra.Command, args []string) error {
	if err := validateScanOptions(); err != nil {
		return err
	}

	if !scanJSIntel && (scanJSIntelGeneric || scanJSIntelNPMCheck) {
		scanJSIntel = true
	}

	// Any crawl-specific flag implies --crawl
	if !scanCrawl {
		crawlFlags := []string{"crawl-headless", "crawl-js-crawl", "crawl-depth", "crawl-concurrency",
			"crawl-rate-limit", "crawl-host-rate-limit", "crawl-timeout", "crawl-extensions",
			"crawl-scope", "crawl-base-url", "crawl-max-domain-pages", "crawl-chrome-data-dir",
			"crawl-chrome-ws-url", "crawl-system-chrome-path", "crawl-use-installed-chrome",
			"crawl-no-incognito", "crawl-no-sandbox", "crawl-automatic-form-fill", "crawl-auth"}
		for _, name := range crawlFlags {
			if cmd.Flags().Changed(name) {
				scanCrawl = true
				break
			}
		}
	}

	// Crawl mode: spider a URL target and scan discovered files
	if scanCrawl {
		if len(args) == 0 {
			return fmt.Errorf("--crawl requires a URL target argument")
		}
		target := args[0]
		if !isHTTPURL(target) {
			return fmt.Errorf("--crawl requires an HTTP(S) URL target, got: %s", target)
		}
		return runCrawlScan(cmd, target)
	}

	// Determine if we're in URL mode
	urls, err := collectURLs(cmd, args)
	if err != nil {
		return err
	}

	if urls != nil {
		return runURLScan(cmd, urls)
	}

	if len(args) == 0 {
		return fmt.Errorf("requires a target argument or --url-file flag")
	}

	target := args[0]

	// Check if target is a GitHub or GitLab URL
	if repoTarget, ok := parseRepoURL(target); ok {
		return runRepoScan(cmd, repoTarget)
	}

	// Validate target exists (filesystem path)
	if _, err := os.Stat(target); err != nil {
		return fmt.Errorf("target does not exist: %s", target)
	}

	// Create enumerator
	enumerator, err := createEnumerator(target, scanGit)
	if err != nil {
		return fmt.Errorf("creating enumerator: %w", err)
	}

	return runEnumeratorScan(cmd, enumerator)
}

// collectURLs determines if the scan should operate in URL mode and returns the URL list.
// Returns nil if not in URL mode.
func collectURLs(cmd *cobra.Command, args []string) ([]string, error) {
	if scanURLFile != "" {
		return readURLFile(scanURLFile)
	}

	if len(args) == 1 && isHTTPURL(args[0]) {
		if _, ok := parseRepoURL(args[0]); !ok {
			return []string{args[0]}, nil
		}
	}

	return nil, nil
}

func isHTTPURL(s string) bool {
	return strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://")
}

func readURLFile(path string) ([]string, error) {
	var r io.Reader
	if path == "-" {
		r = os.Stdin
	} else {
		f, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("opening URL file: %w", err)
		}
		defer f.Close()
		r = f
	}

	var urls []string
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		urls = append(urls, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading URL file: %w", err)
	}
	if len(urls) == 0 {
		return nil, fmt.Errorf("no URLs found in %s", path)
	}
	return urls, nil
}

func runURLScan(cmd *cobra.Command, urls []string) error {
	if !cmd.Flags().Changed("output") {
		scanOutputPath = ":memory:"
	}

	enumerator := enum.NewURLEnumerator(urls, scanMaxFileSize)
	return runEnumeratorScan(cmd, enumerator)
}

func runCrawlScan(cmd *cobra.Command, targetURL string) error {
	if !cmd.Flags().Changed("output") {
		scanOutputPath = ":memory:"
	}

	var timeout time.Duration
	if scanCrawlTimeout != "" {
		var err error
		timeout, err = time.ParseDuration(scanCrawlTimeout)
		if err != nil {
			return fmt.Errorf("invalid --crawl-timeout: %w", err)
		}
	}

	extensions := splitCommaList(scanCrawlExtensions)

	enumerator := enum.NewCrawlEnumerator(enum.CrawlConfig{
		TargetURL:          targetURL,
		BaseURL:            scanCrawlBaseURL,
		MaxDepth:           scanCrawlDepth,
		Concurrency:        scanCrawlConcurrency,
		RateLimit:          scanCrawlRateLimit,
		HostRateLimit:      scanCrawlHostRateLimit,
		Timeout:            timeout,
		Headless:           scanCrawlHeadless,
		JSCrawl:            scanCrawlJSCrawl,
		Extensions:         extensions,
		Scope:              scanCrawlScope,
		MaxSize:            scanMaxFileSize,
		MaxDomainPages:     scanCrawlMaxDomainPages,
		ChromeDataDir:      scanCrawlChromeDataDir,
		ChromeWSURL:        scanCrawlChromeWSURL,
		SystemChromePath:   scanCrawlSystemChrome,
		NoIncognito:        scanCrawlNoIncognito,
		NoSandbox:          scanCrawlNoSandbox,
		AutomaticFormFill:  scanCrawlAutoFormFill,
		AuthCredentials:    scanCrawlAuth,
		UseInstalledChrome: scanCrawlInstalledChrome,
	})

	return runEnumeratorScan(cmd, enumerator)
}

func validateScanOptions() error {
	switch scanOutputFormat {
	case "human", "json", "sarif":
	default:
		return fmt.Errorf("unknown output format: %s", scanOutputFormat)
	}
	if scanMaxFileSize < 0 {
		return fmt.Errorf("--max-file-size must be >= 0")
	}
	if scanContextLines < 0 {
		return fmt.Errorf("--context-lines must be >= 0")
	}
	if scanWorkers < 1 {
		return fmt.Errorf("--workers must be >= 1")
	}
	if scanValidateWorkers < 1 {
		return fmt.Errorf("--validate-workers must be >= 1")
	}
	if extractMaxDepth < 0 {
		return fmt.Errorf("--extract-max-depth must be >= 0")
	}
	if extractMaxSize != "" {
		size, err := parseSize(extractMaxSize)
		if err != nil {
			return fmt.Errorf("parsing extract-max-size: %w", err)
		}
		if size <= 0 {
			return fmt.Errorf("extract-max-size must be greater than 0")
		}
	}
	if extractMaxTotal != "" {
		size, err := parseSize(extractMaxTotal)
		if err != nil {
			return fmt.Errorf("parsing extract-max-total: %w", err)
		}
		if size <= 0 {
			return fmt.Errorf("extract-max-total must be greater than 0")
		}
	}
	if scanSQLiteRowLimit < 0 {
		return fmt.Errorf("--sqlite-row-limit must be >= 0")
	}
	if scanCrawlDepth < 1 {
		return fmt.Errorf("--crawl-depth must be >= 1")
	}
	if scanCrawlConcurrency < 1 {
		return fmt.Errorf("--crawl-concurrency must be >= 1")
	}
	if scanCrawlRateLimit < 0 {
		return fmt.Errorf("--crawl-rate-limit must be >= 0")
	}
	if scanCrawlHostRateLimit < 0 {
		return fmt.Errorf("--crawl-host-rate-limit must be >= 0")
	}
	if scanCrawlMaxDomainPages < 0 {
		return fmt.Errorf("--crawl-max-domain-pages must be >= 0")
	}
	return nil
}

func splitCommaList(value string) []string {
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

// runEnumeratorScan is the shared scan logic for any enumerator (filesystem, URL, etc.).
func runEnumeratorScan(cmd *cobra.Command, enumerator enum.Enumerator) error {
	if quiet {
		restoreEnumLog := enum.SetLogOutput(io.Discard)
		defer restoreEnumLog()
	}

	// Load rules
	rules, err := loadRules(scanRulesPath, scanRulesInclude, scanRulesExclude)
	if err != nil {
		return fmt.Errorf("loading rules: %w", err)
	}

	// Create rule map for finding ID computation
	ruleMap := make(map[string]*types.Rule)
	for _, r := range rules {
		ruleMap[r.ID] = r
	}

	// Create matcher
	m, err := matcher.New(matcher.Config{
		Rules:        rules,
		ContextLines: scanContextLines,
	})
	if err != nil {
		return fmt.Errorf("creating matcher: %w", err)
	}
	defer m.Close()

	// Create store (memory or datastore)
	s, ds, err := openScanStore(scanOutputPath, scanStoreBlobs)
	if err != nil {
		return err
	}
	if ds != nil {
		defer ds.Close()
	} else {
		defer s.Close()
	}

	// Store rules for foreign key constraints
	for _, r := range rules {
		if err := s.AddRule(r); err != nil {
			return fmt.Errorf("storing rule: %w", err)
		}
	}

	// Initialize validation engine (nil if validation disabled)
	validationEngine := initValidationEngine()

	// Prepare inline output for human format
	var outputMu sync.Mutex
	inlineHuman := scanOutputFormat == "human" && !quiet
	var sty *styles
	if inlineHuman {
		sty = scanStyles()
	}

	// Scan with parallel workers
	ctx := context.Background()
	var matchCount atomic.Int64
	var findingCount atomic.Int64
	var skippedCount atomic.Int64
	var totalBytes atomic.Int64
	var blobCount atomic.Int64
	var jsIntelArtifactCount atomic.Int64
	startTime := time.Now()

	var jsAnalyzer *jsintel.Analyzer
	if scanJSIntel {
		cfg := jsintel.DefaultConfig()
		cfg.SourceMaps = scanJSIntelSourceMaps
		cfg.GenericSecrets = scanJSIntelGeneric
		cfg.NPMCheck = scanJSIntelNPMCheck
		jsAnalyzer = jsintel.New(cfg)
	}

	numWorkers := scanWorkers
	if numWorkers < 1 {
		numWorkers = 1
	}
	jobs := make(chan blobJob, 2*numWorkers)

	g, ctx := errgroup.WithContext(ctx)

	// Producer: enumerate blobs and send to workers (NO DB writes)
	g.Go(func() error {
		defer close(jobs)
		enqueue := func(content []byte, blobID types.BlobID, prov types.Provenance) error {
			totalBytes.Add(int64(len(content)))
			blobCount.Add(1)

			// Check for incremental scanning
			if scanIncremental {
				exists, err := s.BlobExists(blobID)
				if err != nil {
					return fmt.Errorf("checking blob: %w", err)
				}
				if exists {
					skippedCount.Add(1)
					return nil
				}
			}

			select {
			case jobs <- blobJob{content: content, blobID: blobID, prov: prov}:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		}

		return enumerator.Enumerate(ctx, func(content []byte, blobID types.BlobID, prov types.Provenance) error {
			if err := enqueue(content, blobID, prov); err != nil {
				return err
			}

			if jsAnalyzer == nil {
				return nil
			}

			result := jsAnalyzer.Analyze(content, prov.Path())
			if len(result.Findings) > 0 {
				jsIntelArtifactCount.Add(int64(len(result.Findings)))
				if inlineHuman {
					outputMu.Lock()
					printJSIntelFindings(cmd, sty, prov, result.Findings)
					outputMu.Unlock()
				}
			}
			for _, warning := range result.Warnings {
				if !quiet {
					fmt.Fprintf(cmd.ErrOrStderr(), "warning: JS intelligence: %s\n", warning)
				}
			}
			for _, source := range result.Sources {
				if int64(len(source.Content)) > scanMaxFileSize {
					if !quiet {
						fmt.Fprintf(cmd.ErrOrStderr(), "warning: source-map source too large, skipping: %s\n", source.Path)
					}
					continue
				}
				derivedProv := sourceMapProvenance(prov.Path(), source.Path)
				if err := enqueue(source.Content, types.ComputeBlobID(source.Content), derivedProv); err != nil {
					return err
				}
			}
			return nil
		})
	})

	// Consumer workers: match, compute line/col, validate, write to DB in batches
	const batchSize = 64
	for i := 0; i < numWorkers; i++ {
		g.Go(func() error {
			type batchItem struct {
				blobID  types.BlobID
				prov    types.Provenance
				content []byte
				size    int64
				matches []*types.Match
			}
			var batch []batchItem

			flush := func() error {
				if len(batch) == 0 {
					return nil
				}
				err := s.ExecBatch(func(tx store.Store) error {
					for _, item := range batch {
						if ds != nil && ds.BlobStore != nil {
							storedID, err := ds.BlobStore.Store(item.content)
							if err != nil {
								return fmt.Errorf("storing blob content: %w", err)
							}
							if storedID != item.blobID {
								return fmt.Errorf("blob content hash mismatch: metadata=%s content=%s", item.blobID.Hex(), storedID.Hex())
							}
						}
						if err := tx.AddBlob(item.blobID, item.size); err != nil {
							return fmt.Errorf("storing blob: %w", err)
						}
						if err := tx.AddProvenance(item.blobID, item.prov); err != nil {
							return fmt.Errorf("storing provenance: %w", err)
						}
						for _, match := range item.matches {
							if err := tx.AddMatch(match); err != nil {
								return fmt.Errorf("storing match: %w", err)
							}
							rule, ok := ruleMap[match.RuleID]
							if !ok {
								return fmt.Errorf("rule not found: %s", match.RuleID)
							}
							findingID := types.ComputeFindingID(rule.StructuralID, match.Groups)
							exists, err := tx.FindingExists(findingID)
							if err != nil {
								return fmt.Errorf("checking finding: %w", err)
							}
							if !exists {
								findingCount.Add(1)
								if err := tx.AddFinding(&types.Finding{
									ID:     findingID,
									RuleID: match.RuleID,
									Groups: match.Groups,
								}); err != nil {
									return fmt.Errorf("storing finding: %w", err)
								}
							}
						}
					}
					return nil
				})
				batch = batch[:0]
				return err
			}

			for job := range jobs {
				matches, err := m.MatchWithBlobID(job.content, job.blobID)
				if err != nil {
					if !quiet {
						fmt.Fprintf(os.Stderr, "[warn] match error (skipping blob %s): %v\n", job.blobID.Hex(), err)
					}
					continue
				}

				for _, match := range matches {
					startLine, startCol := types.ComputeLineColumn(job.content, int(match.Location.Offset.Start))
					endLine, endCol := types.ComputeLineColumn(job.content, int(match.Location.Offset.End))
					match.Location.Source.Start.Line = startLine
					match.Location.Source.Start.Column = startCol
					match.Location.Source.End.Line = endLine
					match.Location.Source.End.Column = endCol
				}

				validateMatches(ctx, validationEngine, matches, verbose)
				matchCount.Add(int64(len(matches)))

				// Inline per-file reporting for human format
				if inlineHuman && len(matches) > 0 {
					outputMu.Lock()
					printFileMatches(cmd, sty, job.prov, matches, ruleMap)
					outputMu.Unlock()
				}

				batch = append(batch, batchItem{
					blobID:  job.blobID,
					prov:    job.prov,
					content: job.content,
					size:    int64(len(job.content)),
					matches: matches,
				})
				if len(batch) >= batchSize {
					if err := flush(); err != nil {
						return err
					}
				}
			}
			return flush()
		})
	}

	if err := g.Wait(); err != nil {
		return fmt.Errorf("scanning: %w", err)
	}

	duration := time.Since(startTime)
	printScanStats(cmd, scanOutputFormat, scanOutputPath,
		totalBytes.Load(), blobCount.Load(), matchCount.Load(), skippedCount.Load(), duration)

	return outputScanResults(cmd, s, rules, ruleMap, jsIntelArtifactCount.Load())
}

// =============================================================================
// HELPERS
// =============================================================================

func loadRules(path, include, exclude string) ([]*types.Rule, error) {
	loader := rule.NewLoader()

	var rules []*types.Rule
	var err error

	if path != "" {
		rules, err = loader.LoadRulesPath(path)
		if err != nil {
			return nil, err
		}
	} else {
		// Builtin rules
		rules, err = loader.LoadBuiltinRules()
		if err != nil {
			return nil, err
		}
	}

	// Apply filtering if patterns specified
	if include != "" || exclude != "" {
		config := rule.FilterConfig{
			Include: rule.ParsePatterns(include),
			Exclude: rule.ParsePatterns(exclude),
		}
		rules, err = rule.Filter(rules, config)
		if err != nil {
			return nil, fmt.Errorf("filtering rules: %w", err)
		}
	}

	return rules, nil
}

// openScanStore creates the store backend based on the output path configuration.
func openScanStore(outputPath string, storeBlobs bool) (store.Store, *datastore.Datastore, error) {
	if outputPath == ":memory:" {
		s, err := store.New(store.Config{Path: ":memory:"})
		if err != nil {
			return nil, nil, fmt.Errorf("creating store: %w", err)
		}
		return s, nil, nil
	}

	ds, err := datastore.Open(outputPath, datastore.Options{
		StoreBlobs: storeBlobs,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("creating datastore: %w", err)
	}
	return ds.Store, ds, nil
}

// printScanStats formats and prints scan statistics.
func printScanStats(cmd *cobra.Command, format, outputPath string, totalBytes, blobCount, matchCount, skippedCount int64, duration time.Duration) {
	if quiet {
		return
	}
	speed := float64(totalBytes) / duration.Seconds()
	newMatches := matchCount - skippedCount
	statsLine := fmt.Sprintf("Scanned %d B from %d blobs in %d second (%.0f B/s); %d/%d new matches\n",
		totalBytes, blobCount, int(duration.Seconds()), speed, newMatches, matchCount)

	if format == "json" || format == "sarif" {
		fmt.Fprint(cmd.ErrOrStderr(), statsLine)
		if outputPath != ":memory:" {
			fmt.Fprintf(cmd.ErrOrStderr(), "Results stored in: %s/datastore.db\n\n", outputPath)
		}
	} else {
		fmt.Fprint(cmd.OutOrStdout(), statsLine)
		fmt.Fprintf(cmd.OutOrStdout(), "\n")
	}
}

// outputScanResults routes scan output to the appropriate formatter based on scanOutputFormat.
func outputScanResults(cmd *cobra.Command, s store.Store, rules []*types.Rule, ruleMap map[string]*types.Rule, jsIntelCount int64) error {
	if quiet {
		return nil
	}

	if scanOutputFormat == "json" {
		matches, err := s.GetAllMatches()
		if err != nil {
			return fmt.Errorf("retrieving matches: %w", err)
		}
		return outputMatches(cmd, matches)
	}

	if scanOutputFormat == "sarif" {
		matches, err := s.GetAllMatches()
		if err != nil {
			return fmt.Errorf("retrieving matches: %w", err)
		}
		return outputSARIF(cmd, s, rules, matches)
	}

	// Human format: inline reporting already printed per-file results,
	// just print a final summary count.
	findings, err := s.GetFindings()
	if err != nil {
		return fmt.Errorf("retrieving findings: %w", err)
	}

	allMatches, err := s.GetAllMatches()
	if err != nil {
		return fmt.Errorf("retrieving matches: %w", err)
	}

	return outputScanSummary(cmd, findings, allMatches, ruleMap, jsIntelCount)
}

// parseSize converts size strings like "10MB" to bytes.
func parseSize(sizeStr string) (int64, error) {
	sizeStr = strings.TrimSpace(strings.ToUpper(sizeStr))

	// Parse multiplier suffix
	multiplier := int64(1)
	if strings.HasSuffix(sizeStr, "KB") {
		multiplier = 1024
		sizeStr = strings.TrimSuffix(sizeStr, "KB")
	} else if strings.HasSuffix(sizeStr, "MB") {
		multiplier = 1024 * 1024
		sizeStr = strings.TrimSuffix(sizeStr, "MB")
	} else if strings.HasSuffix(sizeStr, "GB") {
		multiplier = 1024 * 1024 * 1024
		sizeStr = strings.TrimSuffix(sizeStr, "GB")
	}

	// Parse numeric value
	val, err := strconv.ParseInt(strings.TrimSpace(sizeStr), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid size format: %s", sizeStr)
	}

	return val * multiplier, nil
}

func createEnumerator(target string, useGit bool) (enum.Enumerator, error) {
	// Parse extraction limits
	limits := enum.DefaultExtractionLimits()

	if extractMaxSize != "" {
		size, err := parseSize(extractMaxSize)
		if err != nil {
			return nil, fmt.Errorf("parsing extract-max-size: %w", err)
		}
		if size <= 0 {
			return nil, fmt.Errorf("extract-max-size must be greater than 0")
		}
		limits.MaxSize = size
	}

	if extractMaxTotal != "" {
		size, err := parseSize(extractMaxTotal)
		if err != nil {
			return nil, fmt.Errorf("parsing extract-max-total: %w", err)
		}
		if size <= 0 {
			return nil, fmt.Errorf("extract-max-total must be greater than 0")
		}
		limits.MaxTotal = size
	}

	limits.MaxDepth = extractMaxDepth
	limits.SQLiteRowLimit = scanSQLiteRowLimit

	config := enum.Config{
		Root:            target,
		IncludeHidden:   scanIncludeHidden,
		MaxFileSize:     scanMaxFileSize,
		FollowSymlinks:  false,
		ExtractArchives: string(scanExtractArchivesFlag),
		ExtractLimits:   limits,
	}

	if useGit {
		gitEnum := enum.NewGitEnumerator(config)
		gitEnum.WalkAll = true
		fsEnum := enum.NewFilesystemEnumerator(config)
		return enum.NewCombinedEnumerator(gitEnum, fsEnum), nil
	}

	return enum.NewFilesystemEnumerator(config), nil
}

// repoTarget holds parsed repository URL information.
type repoTarget struct {
	Platform string // "github" or "gitlab"
	Owner    string // org/user
	Repo     string // repository/project name
	FullPath string // "owner/repo" or full GitLab namespace path
}

// parseRepoURL detects if a target string is a GitHub or GitLab repository reference.
// Supports formats:
//   - github.com/owner/repo
//   - https://github.com/owner/repo
//   - https://github.com/owner/repo.git
//   - gitlab.com/namespace/project
//   - https://gitlab.com/namespace/project
func parseRepoURL(target string) (repoTarget, bool) {
	// Strip common URL prefixes
	cleaned := target
	cleaned = strings.TrimPrefix(cleaned, "https://")
	cleaned = strings.TrimPrefix(cleaned, "http://")
	cleaned = strings.TrimSuffix(cleaned, ".git")
	cleaned = strings.TrimSuffix(cleaned, "/")

	parts := strings.SplitN(cleaned, "/", 2) // host/path
	if len(parts) != 2 {
		return repoTarget{}, false
	}
	host := strings.ToLower(parts[0])
	pathParts := splitPath(parts[1])

	var platform string
	var owner, repo, fullPath string
	switch host {
	case "github.com":
		if len(pathParts) < 2 {
			return repoTarget{}, false
		}
		platform = "github"
		owner = pathParts[0]
		repo = pathParts[1]
		fullPath = owner + "/" + repo
	case "gitlab.com":
		if routeIndex := indexPathPart(pathParts, "-"); routeIndex >= 0 {
			pathParts = pathParts[:routeIndex]
		}
		if len(pathParts) < 2 {
			return repoTarget{}, false
		}
		platform = "gitlab"
		owner = pathParts[0]
		repo = pathParts[len(pathParts)-1]
		fullPath = strings.Join(pathParts, "/")
	default:
		return repoTarget{}, false
	}

	return repoTarget{
		Platform: platform,
		Owner:    owner,
		Repo:     repo,
		FullPath: fullPath,
	}, true
}

func splitPath(value string) []string {
	parts := strings.Split(value, "/")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func indexPathPart(parts []string, value string) int {
	for i, part := range parts {
		if part == value {
			return i
		}
	}
	return -1
}

// runRepoScan handles scanning of GitHub/GitLab repositories detected from URL-like targets.
func runRepoScan(cmd *cobra.Command, rt repoTarget) error {
	// Resolve token from environment
	var token string
	switch rt.Platform {
	case "github":
		token = os.Getenv("GITHUB_TOKEN")
	case "gitlab":
		token = os.Getenv("GITLAB_TOKEN")
	}

	if token == "" && !quiet {
		fmt.Fprintf(cmd.ErrOrStderr(), "Note: No %s token provided. Using unauthenticated access (public repos only).\n\n", rt.Platform)
	}

	// Build clone URL
	var cloneURL string
	switch rt.Platform {
	case "github":
		cloneURL = "https://github.com/" + rt.FullPath + ".git"
	case "gitlab":
		cloneURL = "https://gitlab.com/" + rt.FullPath + ".git"
	}

	repos := []enum.RepoInfo{{
		Name:     rt.FullPath,
		CloneURL: cloneURL,
	}}

	cloneEnum := enum.NewCloneEnumerator(repos, enum.Config{
		MaxFileSize: scanMaxFileSize,
	})
	cloneEnum.Git = scanGit

	return runEnumeratorScan(cmd, cloneEnum)
}

// scanStyles returns color styles for inline scan output.
func scanStyles() *styles {
	switch reportColor {
	case "always":
		color.NoColor = false
	case "never":
		color.NoColor = true
	default:
		if !term.IsTerminal(int(os.Stdout.Fd())) || os.Getenv("NO_COLOR") != "" {
			color.NoColor = true
		} else {
			color.NoColor = false
		}
	}
	return newStyles(!color.NoColor)
}

// printFileMatches prints all matches for a single file/URL in consolidated format.
func printFileMatches(cmd *cobra.Command, sty *styles, prov types.Provenance, matches []*types.Match, ruleMap map[string]*types.Rule) {
	out := cmd.OutOrStdout()
	filePath := prov.Path()

	// File header
	header := fmt.Sprintf("── %s ", filePath)
	padLen := 80 - len(header)
	if padLen < 4 {
		padLen = 4
	}
	fmt.Fprintf(out, "%s%s\n", sty.metadata.Sprint(header), sty.metadata.Sprint(strings.Repeat("─", padLen)))

	for _, match := range matches {
		ruleName := match.RuleID
		if r, ok := ruleMap[match.RuleID]; ok {
			ruleName = r.Name
		}

		lineInfo := ""
		if match.Location.Source.Start.Line > 0 {
			lineInfo = fmt.Sprintf("Line %d:%d-%d:%d",
				match.Location.Source.Start.Line, match.Location.Source.Start.Column,
				match.Location.Source.End.Line, match.Location.Source.End.Column)
		}

		fmt.Fprintf(out, "  %s  %s\n", sty.ruleName.Sprint(ruleName), sty.heading.Sprint(lineInfo))

		// Capture groups
		for j, group := range match.Groups {
			fmt.Fprintf(out, "    %s %s\n",
				sty.heading.Sprintf("Group %d:", j+1),
				sty.match.Sprint(string(group)))
		}

		// Context snippet
		parts := formatSnippetWithParts(match.Snippet.Before, match.Snippet.Matching, match.Snippet.After, 500)
		if parts.matching != "" {
			fmt.Fprintf(out, "    %s%s%s%s%s\n",
				parts.prefix,
				parts.before,
				sty.match.Sprint(parts.matching),
				parts.after,
				parts.suffix)
		}

		// Validation status
		if match.ValidationResult != nil {
			fmt.Fprintf(out, "    %s %s\n",
				sty.heading.Sprint("Validation:"),
				match.ValidationResult.Status)
		}

		fmt.Fprintln(out)
	}
}

func printJSIntelFindings(cmd *cobra.Command, sty *styles, prov types.Provenance, findings []jsintel.Finding) {
	out := cmd.OutOrStdout()
	filePath := prov.Path()
	if filePath == "" {
		filePath = "<unknown>"
	}

	jsintel.SortFindings(findings)
	header := fmt.Sprintf("── JS intelligence: %s ", filePath)
	padLen := 80 - len(header)
	if padLen < 4 {
		padLen = 4
	}
	fmt.Fprintf(out, "%s%s\n", sty.metadata.Sprint(header), sty.metadata.Sprint(strings.Repeat("─", padLen)))

	for _, finding := range findings {
		lineInfo := ""
		if finding.Line > 0 {
			lineInfo = fmt.Sprintf("Line %d:%d", finding.Line, finding.Column)
		}

		details := []string{finding.Confidence}
		if finding.Method != "" {
			details = append(details, finding.Method)
		}
		if finding.Detail != "" {
			details = append(details, finding.Detail)
		}
		if finding.Active {
			details = append(details, "active-check")
		}

		fmt.Fprintf(out, "  %s  %s\n", sty.ruleName.Sprint(string(finding.Category)), sty.heading.Sprint(lineInfo))
		fmt.Fprintf(out, "    %s %s\n", sty.heading.Sprint("Value:"), sty.match.Sprint(jsintel.DisplayValue(finding)))
		fmt.Fprintf(out, "    %s %s\n\n", sty.heading.Sprint("Detail:"), strings.Join(details, ", "))
	}
}

func sourceMapProvenance(parentPath, sourcePath string) types.Provenance {
	sourcePath = strings.ReplaceAll(sourcePath, "\n", "")
	sourcePath = strings.ReplaceAll(sourcePath, "\r", "")
	if sourcePath == "" {
		sourcePath = "source.js"
	}

	displayPath := "source-map/" + sourcePath
	if parentPath != "" {
		displayPath = parentPath + "::" + displayPath
	}

	return types.ExtendedProvenance{
		Payload: map[string]interface{}{
			"kind":   "source_map",
			"path":   displayPath,
			"source": parentPath,
			"member": sourcePath,
		},
	}
}

// outputScanSummary prints a compact summary after inline reporting.
func outputScanSummary(cmd *cobra.Command, findings []*types.Finding, matches []*types.Match, ruleMap map[string]*types.Rule, jsIntelCount int64) error {
	if len(findings) == 0 && len(matches) == 0 {
		if jsIntelCount > 0 {
			fmt.Fprintf(cmd.OutOrStdout(), "No LeakLens secret findings. JS intelligence reported %d artifact(s).\n", jsIntelCount)
			return nil
		}
		fmt.Fprintf(cmd.OutOrStdout(), "No findings.\n")
		return nil
	}

	// Build aggregation by rule
	type ruleStats struct {
		name     string
		findings int
	}
	statsMap := make(map[string]*ruleStats)

	for _, f := range findings {
		r, ok := ruleMap[f.RuleID]
		if !ok {
			continue
		}
		if _, exists := statsMap[f.RuleID]; !exists {
			statsMap[f.RuleID] = &ruleStats{name: r.Name}
		}
		statsMap[f.RuleID].findings++
	}

	fmt.Fprintf(cmd.OutOrStdout(), "Summary: %d unique findings, %d total matches across %d rules\n",
		len(findings), len(matches), len(statsMap))
	if jsIntelCount > 0 {
		fmt.Fprintf(cmd.OutOrStdout(), "JS intelligence: %d artifact(s)\n", jsIntelCount)
	}

	return nil
}

func outputMatches(cmd *cobra.Command, matches []*types.Match) error {
	encoder := json.NewEncoder(cmd.OutOrStdout())
	encoder.SetIndent("", "  ")
	return encoder.Encode(matches)
}

func outputFindings(cmd *cobra.Command, findings []*types.Finding) error {
	switch scanOutputFormat {
	case "json":
		encoder := json.NewEncoder(cmd.OutOrStdout())
		encoder.SetIndent("", "  ")
		return encoder.Encode(findings)
	case "human":
		if len(findings) == 0 {
			fmt.Fprintf(cmd.OutOrStdout(), "\nNo findings.\n")
			return nil
		}

		fmt.Fprintf(cmd.OutOrStdout(), "\nFindings:\n")
		for i, f := range findings {
			fmt.Fprintf(cmd.OutOrStdout(), "%d. Rule: %s", i+1, f.RuleID)

			// Show validation status if available
			if len(f.Matches) > 0 && f.Matches[0].ValidationResult != nil {
				vr := f.Matches[0].ValidationResult
				fmt.Fprintf(cmd.OutOrStdout(), " [%s]", vr.Status)
			}
			fmt.Fprintln(cmd.OutOrStdout())
		}
		return nil
	default:
		return fmt.Errorf("unknown output format: %s", scanOutputFormat)
	}
}

// outputSARIF outputs matches in SARIF 2.1.0 format
func outputSARIF(cmd *cobra.Command, s store.Store, rules []*types.Rule, matches []*types.Match) error {
	// Create SARIF report
	report := sarif.NewReport()

	// Add all rules
	for _, rule := range rules {
		report.AddRule(rule)
	}

	// Cache provenance by blob ID to avoid repeated queries
	provenanceCache := make(map[types.BlobID]string)

	// Get provenance for each match and add results
	for _, match := range matches {
		// Check cache first
		filePath, ok := provenanceCache[match.BlobID]
		if !ok {
			// Query provenance
			prov, err := s.GetProvenance(match.BlobID)
			if err != nil {
				// If no provenance found, use blob ID as fallback
				filePath = match.BlobID.Hex()
			} else {
				filePath = prov.Path()
			}
			provenanceCache[match.BlobID] = filePath
		}

		report.AddResult(match, filePath)
	}

	// Serialize to JSON
	jsonBytes, err := report.ToJSON()
	if err != nil {
		return fmt.Errorf("serializing SARIF: %w", err)
	}

	// Write to stdout
	_, err = cmd.OutOrStdout().Write(jsonBytes)
	if err != nil {
		return fmt.Errorf("writing SARIF output: %w", err)
	}

	return nil
}

// initValidationEngine creates the validation engine if validation is enabled.
func initValidationEngine() *validator.Engine {
	if !scanValidate {
		return nil
	}

	var validators []validator.Validator

	// Add Go validators (complex multi-credential validation)
	validators = append(validators, validator.NewAWSValidator())
	validators = append(validators, validator.NewSauceLabsValidator())
	validators = append(validators, validator.NewTwilioValidator())
	validators = append(validators, validator.NewAzureStorageValidator())
	validators = append(validators, validator.NewPostgresValidator())

	// Add embedded YAML validators
	embedded, err := validator.LoadEmbeddedValidators()
	if err != nil {
		// Log warning but continue
		if !quiet {
			fmt.Fprintf(os.Stderr, "warning: failed to load embedded validators: %v\n", err)
		}
	} else {
		validators = append(validators, embedded...)
	}

	return validator.NewEngine(scanValidateWorkers, validators...)
}

// validateMatches validates matches using the validation engine.
func validateMatches(ctx context.Context, engine *validator.Engine, matches []*types.Match, verbose bool) {
	if engine == nil || len(matches) == 0 {
		return
	}

	if verbose && !quiet {
		fmt.Fprintf(os.Stderr, "[validate] Starting validation for %d matches\n", len(matches))
	}

	// Submit all matches for async validation
	results := make([]<-chan *types.ValidationResult, len(matches))
	for i := range matches {
		if verbose && !quiet {
			fmt.Fprintf(os.Stderr, "[validate] Queueing match %d: rule=%s\n", i+1, matches[i].RuleID)
		}
		results[i] = engine.ValidateAsync(ctx, matches[i])
	}

	// Wait for all validations and attach results
	for i, ch := range results {
		result := <-ch
		matches[i].ValidationResult = result
		if verbose && !quiet {
			fmt.Fprintf(os.Stderr, "[validate] Result %d: rule=%s status=%s confidence=%.1f message=%s\n",
				i+1, matches[i].RuleID, result.Status, result.Confidence, result.Message)
		}
	}

	if verbose && !quiet {
		fmt.Fprintf(os.Stderr, "[validate] Validation complete\n")
	}
}
