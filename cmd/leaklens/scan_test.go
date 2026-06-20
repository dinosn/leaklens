package main

import (
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

func TestScanCommand_DefaultOutputIsDatastore(t *testing.T) {
	cmd, _, err := rootCmd.Find([]string{"scan"})
	require.NoError(t, err)

	flag := cmd.Flags().Lookup("output")
	require.NotNil(t, flag, "--output flag should exist")
	assert.Equal(t, "leaklens.ds", flag.DefValue,
		"default --output should be leaklens.ds datastore directory")
}

func TestScanCommand_DefaultCrawlUsesStandardCrawler(t *testing.T) {
	cmd, _, err := rootCmd.Find([]string{"scan"})
	require.NoError(t, err)

	flag := cmd.Flags().Lookup("crawl-headless")
	require.NotNil(t, flag, "--crawl-headless flag should exist")
	assert.Equal(t, "false", flag.DefValue,
		"default --crawl should use the standard crawler and avoid launching Chrome")
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
