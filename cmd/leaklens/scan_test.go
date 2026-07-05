package main

import (
	"os"
	"strings"
	"testing"

	"github.com/dinosn/leaklens/pkg/enum"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestScanCommand_Exists(t *testing.T) {
	cmd, _, err := rootCmd.Find([]string{"scan"})
	require.NoError(t, err)
	assert.Equal(t, "scan", cmd.Name())
}

func TestScanCommand_DefaultOutputIsMemory(t *testing.T) {
	cmd, _, err := rootCmd.Find([]string{"scan"})
	require.NoError(t, err)

	flag := cmd.Flags().Lookup("output")
	require.NotNil(t, flag, "--output flag should exist")
	assert.Equal(t, ":memory:", flag.DefValue,
		"default --output should use an in-memory datastore")
}

func TestScanCommand_DefaultCrawlUsesStandardCrawler(t *testing.T) {
	cmd, _, err := rootCmd.Find([]string{"scan"})
	require.NoError(t, err)

	flag := cmd.Flags().Lookup("crawl-headless")
	require.NotNil(t, flag, "--crawl-headless flag should exist")
	assert.Equal(t, "false", flag.DefValue,
		"default --crawl should use the standard crawler and avoid launching Chrome")
}

func TestScanCommand_DefaultCrawlExtensionsIncludeSourceMaps(t *testing.T) {
	cmd, _, err := rootCmd.Find([]string{"scan"})
	require.NoError(t, err)

	flag := cmd.Flags().Lookup("crawl-extensions")
	require.NotNil(t, flag, "--crawl-extensions flag should exist")
	assert.Equal(t, "js,json,map", flag.DefValue,
		"default crawl extensions should include source maps")
}

func TestScanCommand_DownloadDirFlagExists(t *testing.T) {
	cmd, _, err := rootCmd.Find([]string{"scan"})
	require.NoError(t, err)

	flag := cmd.Flags().Lookup("download-dir")
	require.NotNil(t, flag, "--download-dir flag should exist")
	assert.Contains(t, flag.Usage, "preserving website path structure")
}

func TestExtractStandaloneSourceMapSources(t *testing.T) {
	content := []byte(`{
		"version": 3,
		"sources": ["webpack://app/src/main.js", "webpack://app/src/empty.js", "webpack://app/src/config.js"],
		"sourcesContent": ["const apiKey = \"example-key\";", null, "const mode = \"test\";"]
	}`)

	got, err := extractStandaloneSourceMapSources(content)
	require.NoError(t, err)
	require.Len(t, got, 2)
	assert.Equal(t, "webpack://app/src/main.js", got[0].Path)
	assert.Equal(t, []byte(`const apiKey = "example-key";`), got[0].Content)
	assert.Equal(t, "webpack://app/src/config.js", got[1].Path)
	assert.Equal(t, []byte(`const mode = "test";`), got[1].Content)
}

func TestIsSourceMapBlobPath(t *testing.T) {
	assert.True(t, isSourceMapBlobPath("https://app.example.test/static/js/app.11111111.js.map?cache=1"))
	assert.False(t, isSourceMapBlobPath("https://app.example.test/static/js/app.11111111.js"))
}

func TestScanCommand_HelpDoesNotMentionKatana(t *testing.T) {
	cmd, _, err := rootCmd.Find([]string{"scan"})
	require.NoError(t, err)

	var b strings.Builder
	cmd.SetOut(&b)
	t.Cleanup(func() {
		cmd.SetOut(os.Stdout)
	})
	require.NoError(t, cmd.Help())
	assert.NotContains(t, b.String(), "Katana")
	assert.NotContains(t, b.String(), "katana")
}

func TestCreateEnumerator_GitReturnsCombined(t *testing.T) {
	// createEnumerator with useGit=true must return a *enum.CombinedEnumerator
	// so that both git history and the working tree are scanned.
	target := t.TempDir()

	e, err := createEnumerator(target, true)
	require.NoError(t, err)

	_, ok := e.(*enum.CombinedEnumerator)
	assert.True(t, ok, "createEnumerator(useGit=true) should return *enum.CombinedEnumerator, got %T", e)
}

func TestCreateEnumerator_NoGitReturnsFilesystem(t *testing.T) {
	target := t.TempDir()

	e, err := createEnumerator(target, false)
	require.NoError(t, err)

	_, ok := e.(*enum.FilesystemEnumerator)
	assert.True(t, ok, "createEnumerator(useGit=false) should return *enum.FilesystemEnumerator, got %T", e)
}

func TestCreateEnumerator_InvalidTarget(t *testing.T) {
	// The enumerator creation itself does not validate the target path;
	// that validation happens in runScan. So createEnumerator succeeds
	// regardless of whether the path exists.
	e, err := createEnumerator("/nonexistent/path/xyz", false)
	require.NoError(t, err)
	assert.NotNil(t, e)
}

func init() {
	// Ensure the package-level flag vars have sane defaults for unit tests
	// (they are normally set by cobra flag parsing).
	if extractMaxSize == "" {
		extractMaxSize = "10MB"
	}
	if extractMaxTotal == "" {
		extractMaxTotal = "100MB"
	}
	if extractMaxDepth == 0 {
		extractMaxDepth = 5
	}
}
