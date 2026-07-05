package main

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dinosn/leaklens/pkg/aianalysis"
	"github.com/dinosn/leaklens/pkg/enum"
	"github.com/dinosn/leaklens/pkg/types"
	"github.com/spf13/cobra"
)

type oneBlobEnumerator struct {
	content []byte
	path    string
}

func (e oneBlobEnumerator) Enumerate(ctx context.Context, callback func(content []byte, blobID types.BlobID, prov types.Provenance) error) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	return callback(e.content, types.ComputeBlobID(e.content), types.FileProvenance{FilePath: e.path})
}

type oneURLBlobEnumerator struct {
	content []byte
	rawURL  string
}

func (e oneURLBlobEnumerator) Enumerate(ctx context.Context, callback func(content []byte, blobID types.BlobID, prov types.Provenance) error) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	return callback(e.content, types.ComputeBlobID(e.content), types.URLProvenance{URL: e.rawURL})
}

type contextCheckingAIClient struct {
	calls int
}

func (c *contextCheckingAIClient) Complete(ctx context.Context, req aianalysis.CompletionRequest) (aianalysis.CompletionResponse, error) {
	c.calls++
	if err := ctx.Err(); err != nil {
		return aianalysis.CompletionResponse{}, err
	}
	return aianalysis.CompletionResponse{Text: "AI review complete"}, nil
}

func writeRegressionRule(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "rule.yml")
	data := []byte(`rules:
  - name: Test Secret
    id: test.secret
    pattern: testsecret_[A-Z0-9]+
    categories: [test]
`)
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatalf("failed to write rule: %v", err)
	}
	return path
}

func setScanGlobalsForRegression(t *testing.T, rulePath, outputPath string) {
	t.Helper()

	oldQuiet := quiet
	oldRulesPath := scanRulesPath
	oldRulesInclude := scanRulesInclude
	oldRulesExclude := scanRulesExclude
	oldOutputPath := scanOutputPath
	oldOutputFormat := scanOutputFormat
	oldMaxFileSize := scanMaxFileSize
	oldContextLines := scanContextLines
	oldIncremental := scanIncremental
	oldValidate := scanValidate
	oldValidateWorkers := scanValidateWorkers
	oldStoreBlobs := scanStoreBlobs
	oldDownloadDir := scanDownloadDir
	oldWorkers := scanWorkers
	oldExtractMaxSize := extractMaxSize
	oldExtractMaxTotal := extractMaxTotal
	oldExtractMaxDepth := extractMaxDepth
	oldSQLiteRowLimit := scanSQLiteRowLimit
	oldCrawlDepth := scanCrawlDepth
	oldCrawlConcurrency := scanCrawlConcurrency
	oldCrawlRateLimit := scanCrawlRateLimit
	oldCrawlHostRateLimit := scanCrawlHostRateLimit
	oldCrawlMaxDomainPages := scanCrawlMaxDomainPages
	oldJSIntel := scanJSIntel
	oldJSIntelSourceMaps := scanJSIntelSourceMaps
	oldJSIntelGeneric := scanJSIntelGeneric
	oldJSIntelNPMCheck := scanJSIntelNPMCheck
	oldAI := scanAI
	oldAIMode := scanAIMode
	oldAIReportDir := scanAIReportDir
	oldAICloudRedaction := scanAICloudRedaction
	oldAIProgress := scanAIProgress
	oldAIResume := scanAIResume
	oldAIResolvedReportDir := scanAIResolvedReportDir
	oldAITargetHints := append([]string(nil), scanAITargetHints...)
	oldAIClient := scanAIClient

	t.Cleanup(func() {
		quiet = oldQuiet
		scanRulesPath = oldRulesPath
		scanRulesInclude = oldRulesInclude
		scanRulesExclude = oldRulesExclude
		scanOutputPath = oldOutputPath
		scanOutputFormat = oldOutputFormat
		scanMaxFileSize = oldMaxFileSize
		scanContextLines = oldContextLines
		scanIncremental = oldIncremental
		scanValidate = oldValidate
		scanValidateWorkers = oldValidateWorkers
		scanStoreBlobs = oldStoreBlobs
		scanDownloadDir = oldDownloadDir
		scanWorkers = oldWorkers
		extractMaxSize = oldExtractMaxSize
		extractMaxTotal = oldExtractMaxTotal
		extractMaxDepth = oldExtractMaxDepth
		scanSQLiteRowLimit = oldSQLiteRowLimit
		scanCrawlDepth = oldCrawlDepth
		scanCrawlConcurrency = oldCrawlConcurrency
		scanCrawlRateLimit = oldCrawlRateLimit
		scanCrawlHostRateLimit = oldCrawlHostRateLimit
		scanCrawlMaxDomainPages = oldCrawlMaxDomainPages
		scanJSIntel = oldJSIntel
		scanJSIntelSourceMaps = oldJSIntelSourceMaps
		scanJSIntelGeneric = oldJSIntelGeneric
		scanJSIntelNPMCheck = oldJSIntelNPMCheck
		scanAI = oldAI
		scanAIMode = oldAIMode
		scanAIReportDir = oldAIReportDir
		scanAICloudRedaction = oldAICloudRedaction
		scanAIProgress = oldAIProgress
		scanAIResume = oldAIResume
		scanAIResolvedReportDir = oldAIResolvedReportDir
		scanAITargetHints = oldAITargetHints
		scanAIClient = oldAIClient
	})

	quiet = false
	scanRulesPath = rulePath
	scanRulesInclude = ""
	scanRulesExclude = ""
	scanOutputPath = outputPath
	scanOutputFormat = "human"
	scanMaxFileSize = 1024
	scanContextLines = 1
	scanIncremental = false
	scanValidate = false
	scanValidateWorkers = 1
	scanStoreBlobs = false
	scanDownloadDir = ""
	scanWorkers = 1
	extractMaxSize = "10MB"
	extractMaxTotal = "100MB"
	extractMaxDepth = 5
	scanSQLiteRowLimit = 1000
	scanCrawlDepth = 3
	scanCrawlConcurrency = 2
	scanCrawlRateLimit = 3
	scanCrawlHostRateLimit = 0
	scanCrawlMaxDomainPages = 0
	scanJSIntel = false
	scanJSIntelSourceMaps = true
	scanJSIntelGeneric = false
	scanJSIntelNPMCheck = false
	scanAI = false
	scanAIMode = "all"
	scanAIReportDir = ""
	scanAICloudRedaction = "standard"
	scanAIProgress = "text"
	scanAIResume = false
	scanAIResolvedReportDir = ""
	scanAITargetHints = nil
	scanAIClient = nil
}

func runRegressionScan(t *testing.T, outputPath string) bytes.Buffer {
	t.Helper()
	rulePath := writeRegressionRule(t)
	setScanGlobalsForRegression(t, rulePath, outputPath)

	var out bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&out)
	enumerator := oneBlobEnumerator{
		content: []byte(`const token = "testsecret_ABC123";`),
		path:    filepath.Join(t.TempDir(), "app.js"),
	}
	if err := runEnumeratorScan(cmd, enumerator); err != nil {
		t.Fatalf("runEnumeratorScan failed: %v", err)
	}
	return out
}

func TestRunEnumeratorScan_StoreBlobsWritesContent(t *testing.T) {
	rulePath := writeRegressionRule(t)
	outputPath := filepath.Join(t.TempDir(), "out.ds")
	setScanGlobalsForRegression(t, rulePath, outputPath)
	scanStoreBlobs = true
	quiet = true

	content := []byte(`const token = "testsecret_ABC123";`)
	blobID := types.ComputeBlobID(content)
	cmd := &cobra.Command{}
	if err := runEnumeratorScan(cmd, oneBlobEnumerator{content: content, path: "app.js"}); err != nil {
		t.Fatalf("runEnumeratorScan failed: %v", err)
	}

	blobPath := filepath.Join(outputPath, "blobs", blobID.Hex()[:2], blobID.Hex()[2:])
	stored, err := os.ReadFile(blobPath)
	if err != nil {
		t.Fatalf("expected blob content at %s: %v", blobPath, err)
	}
	if string(stored) != string(content) {
		t.Fatalf("stored blob content mismatch: %q", string(stored))
	}
}

func TestRunEnumeratorScan_ParsesStandaloneSourceMapSources(t *testing.T) {
	rulePath := writeRegressionRule(t)
	setScanGlobalsForRegression(t, rulePath, ":memory:")

	content := []byte(`{
		"version": 3,
		"sources": ["webpack://app/src/config.js"],
		"sourcesContent": ["const token = \"testsecret_\u0041BC123\";"]
	}`)
	var out bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&out)
	err := runEnumeratorScan(cmd, oneURLBlobEnumerator{
		content: content,
		rawURL:  "https://app.example.test/static/js/app.11111111.js.map",
	})
	if err != nil {
		t.Fatalf("runEnumeratorScan failed: %v", err)
	}

	if !strings.Contains(out.String(), "source-map/webpack://app/src/config.js") {
		t.Fatalf("expected source-map-derived provenance in output, got %s", out.String())
	}
	if !strings.Contains(out.String(), "testsecret_ABC123") {
		t.Fatalf("expected source-map-derived secret in output, got %s", out.String())
	}
}

func TestRunEnumeratorScan_DownloadDirMirrorsURLPath(t *testing.T) {
	rulePath := writeRegressionRule(t)
	outputPath := filepath.Join(t.TempDir(), "out.ds")
	downloadDir := filepath.Join(t.TempDir(), "downloaded")
	setScanGlobalsForRegression(t, rulePath, outputPath)
	scanDownloadDir = downloadDir
	quiet = true

	content := []byte(`const token = "testsecret_ABC123";`)
	cmd := &cobra.Command{}
	err := runEnumeratorScan(cmd, oneURLBlobEnumerator{
		content: content,
		rawURL:  "https://static.example.test/app/Scripts/login.js?v=63",
	})
	if err != nil {
		t.Fatalf("runEnumeratorScan failed: %v", err)
	}

	mirroredPath := filepath.Join(downloadDir, "static.example.test", "app", "Scripts", "login__query_v=63.js")
	stored, err := os.ReadFile(mirroredPath)
	if err != nil {
		t.Fatalf("expected mirrored URL content at %s: %v", mirroredPath, err)
	}
	if string(stored) != string(content) {
		t.Fatalf("mirrored URL content mismatch: %q", string(stored))
	}
}

func TestMirroredURLPath(t *testing.T) {
	tests := []struct {
		rawURL string
		want   string
	}{
		{
			rawURL: "https://example.com/iPAS/Scripts/app.js",
			want:   filepath.Join("example.com", "iPAS", "Scripts", "app.js"),
		},
		{
			rawURL: "https://example.com/iPAS/ScriptResources/UserScriptResource_v2.js?v=63",
			want:   filepath.Join("example.com", "iPAS", "ScriptResources", "UserScriptResource_v2__query_v=63.js"),
		},
		{
			rawURL: "https://example.com/iPAS/",
			want:   filepath.Join("example.com", "iPAS", "index"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.rawURL, func(t *testing.T) {
			got, err := mirroredURLPath(tt.rawURL)
			if err != nil {
				t.Fatalf("mirroredURLPath failed: %v", err)
			}
			if got != tt.want {
				t.Fatalf("mirroredURLPath mismatch: got %q want %q", got, tt.want)
			}
		})
	}
}

func TestRunEnumeratorScan_QuietSuppressesOutput(t *testing.T) {
	rulePath := writeRegressionRule(t)
	setScanGlobalsForRegression(t, rulePath, ":memory:")
	quiet = true

	var out bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&out)
	err := runEnumeratorScan(cmd, oneBlobEnumerator{
		content: []byte(`const token = "testsecret_ABC123";`),
		path:    "app.js",
	})
	if err != nil {
		t.Fatalf("runEnumeratorScan failed: %v", err)
	}
	if out.Len() != 0 {
		t.Fatalf("expected quiet scan to suppress stdout, got %q", out.String())
	}
}

func TestRunEnumeratorScan_QuietSuppressesEnumWarnings(t *testing.T) {
	rulePath := writeRegressionRule(t)
	setScanGlobalsForRegression(t, rulePath, ":memory:")
	quiet = true

	var enumErr bytes.Buffer
	restoreLogs := enum.SetLogOutput(&enumErr)
	t.Cleanup(restoreLogs)

	var out bytes.Buffer
	var errOut bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)

	err := runEnumeratorScan(cmd, enum.NewURLEnumerator([]string{"not-a-url"}, 1024))
	if err == nil || !strings.Contains(err.Error(), "all URL fetches failed") {
		t.Fatalf("expected URL fetch failure, got %v", err)
	}
	if out.Len() != 0 {
		t.Fatalf("expected quiet scan to suppress stdout, got %q", out.String())
	}
	if errOut.Len() != 0 {
		t.Fatalf("expected quiet scan to suppress command stderr, got %q", errOut.String())
	}
	if enumErr.Len() != 0 {
		t.Fatalf("expected quiet scan to suppress enum diagnostics, got %q", enumErr.String())
	}
}

func TestValidateScanOptionsRejectsInvalidValues(t *testing.T) {
	rulePath := writeRegressionRule(t)
	setScanGlobalsForRegression(t, rulePath, ":memory:")

	scanOutputFormat = "bogus"
	if err := validateScanOptions(); err == nil || !strings.Contains(err.Error(), "unknown output format") {
		t.Fatalf("expected invalid format error, got %v", err)
	}

	scanOutputFormat = "human"
	scanMaxFileSize = -1
	if err := validateScanOptions(); err == nil || !strings.Contains(err.Error(), "--max-file-size") {
		t.Fatalf("expected negative max-file-size error, got %v", err)
	}

	scanMaxFileSize = 1024
	extractMaxSize = "-1"
	if err := validateScanOptions(); err == nil || !strings.Contains(err.Error(), "extract-max-size") {
		t.Fatalf("expected negative extract-max-size error, got %v", err)
	}
}

func TestValidateScanOptionsRequiresAIEnvOnlyConfiguration(t *testing.T) {
	rulePath := writeRegressionRule(t)
	setScanGlobalsForRegression(t, rulePath, ":memory:")
	scanAI = true

	t.Setenv("LEAKLENS_AI_PROVIDER", "")
	t.Setenv("LEAKLENS_AI_MODEL", "")
	t.Setenv("LEAKLENS_OPENAI_API_KEY", "")
	if err := validateScanOptions(); err == nil || !strings.Contains(err.Error(), "LEAKLENS_AI_PROVIDER") {
		t.Fatalf("expected provider env error, got %v", err)
	}

	t.Setenv("LEAKLENS_AI_PROVIDER", "openai")
	t.Setenv("LEAKLENS_AI_MODEL", "test-model")
	if err := validateScanOptions(); err == nil || !strings.Contains(err.Error(), "LEAKLENS_OPENAI_API_KEY") {
		t.Fatalf("expected openai key env error, got %v", err)
	}

	t.Setenv("LEAKLENS_OPENAI_API_KEY", "test-key")
	if err := validateScanOptions(); err != nil {
		t.Fatalf("expected AI env validation to pass, got %v", err)
	}
}

func TestValidateScanOptionsAcceptsAIRuntimeEnvConfiguration(t *testing.T) {
	rulePath := writeRegressionRule(t)
	setScanGlobalsForRegression(t, rulePath, ":memory:")
	scanAI = true
	t.Setenv("LEAKLENS_AI_PROVIDER", "openai")
	t.Setenv("LEAKLENS_AI_MODEL", "test-model")
	t.Setenv("LEAKLENS_OPENAI_API_KEY", "test-key")
	t.Setenv("LEAKLENS_AI_TIMEOUT", "7m")
	t.Setenv("LEAKLENS_AI_RETRIES", "0")
	t.Setenv("LEAKLENS_AI_CHUNK_CHARS", "12345")
	t.Setenv("LEAKLENS_AI_CONCURRENCY", "4")

	if err := validateScanOptions(); err != nil {
		t.Fatalf("expected AI runtime env validation to pass, got %v", err)
	}
	options, err := aiRuntimeOptionsFromEnv()
	if err != nil {
		t.Fatalf("aiRuntimeOptionsFromEnv failed: %v", err)
	}
	if options.Timeout.String() != "7m0s" || options.Retries != 0 || options.ChunkChars != 12345 || options.Concurrency != 4 {
		t.Fatalf("unexpected AI runtime options: %#v", options)
	}
}

func TestValidateScanOptionsRejectsInvalidAIRuntimeEnvConfiguration(t *testing.T) {
	rulePath := writeRegressionRule(t)
	setScanGlobalsForRegression(t, rulePath, ":memory:")
	scanAI = true
	t.Setenv("LEAKLENS_AI_PROVIDER", "openai")
	t.Setenv("LEAKLENS_AI_MODEL", "test-model")
	t.Setenv("LEAKLENS_OPENAI_API_KEY", "test-key")
	t.Setenv("LEAKLENS_AI_RETRIES", "-1")

	if err := validateScanOptions(); err == nil || !strings.Contains(err.Error(), "LEAKLENS_AI_RETRIES") {
		t.Fatalf("expected invalid retry env error, got %v", err)
	}

	t.Setenv("LEAKLENS_AI_RETRIES", "")
	t.Setenv("LEAKLENS_AI_CONCURRENCY", "0")
	if err := validateScanOptions(); err == nil || !strings.Contains(err.Error(), "LEAKLENS_AI_CONCURRENCY") {
		t.Fatalf("expected invalid concurrency env error, got %v", err)
	}
}

func TestPrepareAIOutputAutoSetsDownloadDirForURLScans(t *testing.T) {
	rulePath := writeRegressionRule(t)
	setScanGlobalsForRegression(t, rulePath, ":memory:")
	scanAI = true
	scanAIReportDir = filepath.Join(t.TempDir(), "ai-report")

	if err := prepareAIOutput("https://www.example.test/app/", true, []string{"https://www.example.test/app/"}); err != nil {
		t.Fatalf("prepareAIOutput failed: %v", err)
	}

	if scanAIResolvedReportDir != scanAIReportDir {
		t.Fatalf("unexpected report dir: got %q want %q", scanAIResolvedReportDir, scanAIReportDir)
	}
	wantDownloadDir := filepath.Join(scanAIReportDir, "downloaded")
	if scanDownloadDir != wantDownloadDir {
		t.Fatalf("unexpected download dir: got %q want %q", scanDownloadDir, wantDownloadDir)
	}
	if len(scanAITargetHints) != 1 || scanAITargetHints[0] != "https://www.example.test/app/" {
		t.Fatalf("unexpected target hints: %#v", scanAITargetHints)
	}
}

func TestRunEnumeratorScan_AIRunsAfterScanWithActiveContext(t *testing.T) {
	rulePath := writeRegressionRule(t)
	setScanGlobalsForRegression(t, rulePath, ":memory:")
	scanAI = true
	scanAIResolvedReportDir = t.TempDir()
	scanAIProgress = "quiet"
	fakeAI := &contextCheckingAIClient{}
	scanAIClient = fakeAI
	t.Setenv("LEAKLENS_AI_PROVIDER", "openai")
	t.Setenv("LEAKLENS_AI_MODEL", "test-model")
	t.Setenv("LEAKLENS_OPENAI_API_KEY", "test-key")

	cmd := &cobra.Command{}
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	err := runEnumeratorScan(cmd, oneBlobEnumerator{
		content: []byte(`fetch("/api/test"); const apiKey = "dummy_secret_value_for_redaction_tests";`),
		path:    "app.js",
	})
	if err != nil {
		t.Fatalf("runEnumeratorScan failed: %v", err)
	}
	if fakeAI.calls == 0 {
		t.Fatal("expected fake AI client to be called")
	}
	if _, err := os.Stat(filepath.Join(scanAIResolvedReportDir, "leaklens-ai-report.md")); err != nil {
		t.Fatalf("expected AI report to be written: %v", err)
	}
}

func TestParseRepoURL_GitLabSubgroupPreserved(t *testing.T) {
	rt, ok := parseRepoURL("https://gitlab.com/group/subgroup/project")
	if !ok {
		t.Fatal("expected GitLab URL to parse")
	}
	if rt.Platform != "gitlab" {
		t.Fatalf("expected gitlab platform, got %s", rt.Platform)
	}
	if rt.FullPath != "group/subgroup/project" {
		t.Fatalf("expected full GitLab path to be preserved, got %s", rt.FullPath)
	}

	rt, ok = parseRepoURL("https://gitlab.com/group/subgroup/project/-/tree/main")
	if !ok {
		t.Fatal("expected GitLab web URL to parse")
	}
	if rt.FullPath != "group/subgroup/project" {
		t.Fatalf("expected GitLab UI route to be trimmed, got %s", rt.FullPath)
	}
}

func TestRunReportSARIF(t *testing.T) {
	outputPath := filepath.Join(t.TempDir(), "out.ds")
	_ = runRegressionScan(t, outputPath)

	oldDatastore := reportDatastore
	oldFormat := reportFormat
	oldColor := reportColor
	oldQuiet := quiet
	t.Cleanup(func() {
		reportDatastore = oldDatastore
		reportFormat = oldFormat
		reportColor = oldColor
		quiet = oldQuiet
	})

	reportDatastore = outputPath
	reportFormat = "sarif"
	reportColor = "never"
	quiet = false

	var out bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&out)
	if err := runReport(cmd, nil); err != nil {
		t.Fatalf("runReport failed: %v", err)
	}
	if !strings.Contains(out.String(), `"version": "2.1.0"`) {
		t.Fatalf("expected SARIF output, got %s", out.String())
	}
	if !strings.Contains(out.String(), `"ruleId": "test.secret"`) {
		t.Fatalf("expected test finding in SARIF output, got %s", out.String())
	}
}

func TestRunReportRejectsInvalidColor(t *testing.T) {
	oldFormat := reportFormat
	oldColor := reportColor
	t.Cleanup(func() {
		reportFormat = oldFormat
		reportColor = oldColor
	})

	reportFormat = "human"
	reportColor = "bogus"
	if err := validateReportOptions(); err == nil || !strings.Contains(err.Error(), "unknown color mode") {
		t.Fatalf("expected invalid color error, got %v", err)
	}
}

func TestRunRulesListLoadsRuleDirectory(t *testing.T) {
	dir := t.TempDir()
	data := []byte(`rules:
  - name: Dir Secret
    id: test.dir
    pattern: dirsecret_[A-Z0-9]+
`)
	if err := os.WriteFile(filepath.Join(dir, "dir.yml"), data, 0644); err != nil {
		t.Fatalf("failed to write rule: %v", err)
	}

	oldRulesPath := rulesPath
	oldInclude := rulesInclude
	oldExclude := rulesExclude
	oldFormat := outputFormat
	oldQuiet := quiet
	t.Cleanup(func() {
		rulesPath = oldRulesPath
		rulesInclude = oldInclude
		rulesExclude = oldExclude
		outputFormat = oldFormat
		quiet = oldQuiet
	})

	rulesPath = dir
	rulesInclude = ""
	rulesExclude = ""
	outputFormat = "json"
	quiet = false

	var out bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&out)
	if err := runRulesList(cmd, nil); err != nil {
		t.Fatalf("runRulesList failed: %v", err)
	}
	if !strings.Contains(out.String(), `"ID": "test.dir"`) {
		t.Fatalf("expected directory rule in output, got %s", out.String())
	}
}
