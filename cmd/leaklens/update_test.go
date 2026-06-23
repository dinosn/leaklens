package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheckForUpdates_Outdated(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "application/vnd.github+json", r.Header.Get("Accept"))
		assert.Equal(t, "leaklens", r.Header.Get("User-Agent"))
		_, _ = w.Write([]byte(`{"tag_name":"v1.2.0","html_url":"https://github.com/dinosn/leaklens/releases/tag/v1.2.0"}`))
	}))
	defer server.Close()

	status, err := checkForUpdates(t.Context(), server.Client(), server.URL, "v1.1.0")
	require.NoError(t, err)
	assert.Equal(t, updateStateOutdated, status.State)
	assert.Equal(t, "v1.1.0", status.Current)
	assert.Equal(t, "v1.2.0", status.Latest)
	assert.Equal(t, "v1.2.0", status.InstallRef)
}

func TestCheckForUpdates_Latest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"tag_name":"v1.2.0"}`))
	}))
	defer server.Close()

	status, err := checkForUpdates(t.Context(), server.Client(), server.URL, "v1.2.0")
	require.NoError(t, err)
	assert.Equal(t, updateStateLatest, status.State)
}

func TestCheckForUpdates_NoRelease(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	defer server.Close()

	status, err := checkForUpdates(t.Context(), server.Client(), server.URL, "source")
	require.NoError(t, err)
	assert.Equal(t, updateStateNoRelease, status.State)
	assert.Equal(t, "source", status.Current)
}

func TestClassifyUpdateStatus_DevelopmentBuild(t *testing.T) {
	status := classifyUpdateStatus("v0.0.0-20260622183434-2448e48447c3", "v1.0.0", "")
	assert.Equal(t, updateStateDevelopment, status.State)

	status = classifyUpdateStatus("v0.1.1-0.20260623064508-b975a091e833", "v0.1.0", "")
	assert.Equal(t, updateStateDevelopment, status.State)
}

func TestCompareReleaseVersions(t *testing.T) {
	cmp, ok := compareReleaseVersions("v1.2.3", "v1.2.4")
	require.True(t, ok)
	assert.Equal(t, -1, cmp)

	cmp, ok = compareReleaseVersions("1.3.0", "v1.2.4")
	require.True(t, ok)
	assert.Equal(t, 1, cmp)

	_, ok = compareReleaseVersions("source", "v1.2.4")
	assert.False(t, ok)
}

func TestPrintUpdateStatus_Outdated(t *testing.T) {
	cmd := &cobra.Command{}
	var errOut bytes.Buffer
	cmd.SetErr(&errOut)

	printUpdateStatus(cmd, updateStatus{
		State:      updateStateOutdated,
		Current:    "v1.0.0",
		Latest:     "v1.1.0",
		LatestURL:  "https://example.test/release",
		InstallRef: "v1.1.0",
	}, false)

	output := errOut.String()
	assert.Contains(t, output, "LeakLens update available: v1.0.0 -> v1.1.0")
	assert.Contains(t, output, "GOPROXY=direct go install github.com/dinosn/leaklens/cmd/leaklens@v1.1.0")
}

func TestRunUpdate_NoRelease(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	defer server.Close()

	restore := setUpdateGlobalsForTest(t)
	defer restore()
	updateCheckURL = server.URL
	manualUpdateCheckTimeout = time.Second

	var out bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&out)

	require.NoError(t, runUpdate(cmd, nil))
	assert.Contains(t, out.String(), "No GitHub release is published for LeakLens yet.")
}

func TestNotifyUpdateStatus_PrintsLatestStatusOnStartup(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"tag_name":"v1.2.0"}`))
	}))
	defer server.Close()

	restore := setUpdateGlobalsForTest(t)
	defer restore()
	version = "v1.2.0"
	updateCheckURL = server.URL
	updateCheckTimeout = time.Second

	var errOut bytes.Buffer
	cmd := &cobra.Command{Use: "scan"}
	cmd.SetErr(&errOut)

	notifyUpdateStatus(cmd, nil)
	assert.Contains(t, errOut.String(), "LeakLens is on the latest release: v1.2.0")
}

func TestNotifyUpdateStatus_SuppressesNoReleaseWithoutVerbose(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	defer server.Close()

	restore := setUpdateGlobalsForTest(t)
	defer restore()
	version = "v1.2.0"
	updateCheckURL = server.URL
	updateCheckTimeout = time.Second

	var errOut bytes.Buffer
	cmd := &cobra.Command{Use: "scan"}
	cmd.SetErr(&errOut)

	notifyUpdateStatus(cmd, nil)
	assert.Empty(t, errOut.String())
}

func TestShouldSkipUpdateCheck(t *testing.T) {
	restore := setUpdateGlobalsForTest(t)
	defer restore()

	cmd := &cobra.Command{Use: "scan"}
	quiet = false
	updateCheckDisabled = false
	assert.False(t, shouldSkipUpdateCheck(cmd))

	quiet = true
	assert.True(t, shouldSkipUpdateCheck(cmd))

	quiet = false
	updateCheckDisabled = true
	assert.True(t, shouldSkipUpdateCheck(cmd))

	updateCheckDisabled = false
	require.NoError(t, os.Setenv("LEAKLENS_NO_UPDATE_CHECK", "true"))
	assert.True(t, shouldSkipUpdateCheck(cmd))

	require.NoError(t, os.Setenv("LEAKLENS_NO_UPDATE_CHECK", "false"))
	assert.False(t, shouldSkipUpdateCheck(cmd))

	assert.True(t, shouldSkipUpdateCheck(updateCmd))
}

func TestShouldPrintStartupUpdateStatus(t *testing.T) {
	restore := setUpdateGlobalsForTest(t)
	defer restore()

	verbose = false
	assert.False(t, shouldPrintStartupUpdateStatus(updateStatus{State: updateStateNoRelease}))
	assert.True(t, shouldPrintStartupUpdateStatus(updateStatus{State: updateStateLatest}))
	assert.True(t, shouldPrintStartupUpdateStatus(updateStatus{State: updateStateOutdated}))

	verbose = true
	assert.True(t, shouldPrintStartupUpdateStatus(updateStatus{State: updateStateNoRelease}))
}

func setUpdateGlobalsForTest(t *testing.T) func() {
	t.Helper()

	oldVersion := version
	oldQuiet := quiet
	oldVerbose := verbose
	oldDisabled := updateCheckDisabled
	oldURL := updateCheckURL
	oldTimeout := updateCheckTimeout
	oldManualTimeout := manualUpdateCheckTimeout
	oldEnv, hadEnv := os.LookupEnv("LEAKLENS_NO_UPDATE_CHECK")

	quiet = false
	verbose = false
	updateCheckDisabled = false
	_ = os.Unsetenv("LEAKLENS_NO_UPDATE_CHECK")

	return func() {
		version = oldVersion
		quiet = oldQuiet
		verbose = oldVerbose
		updateCheckDisabled = oldDisabled
		updateCheckURL = oldURL
		updateCheckTimeout = oldTimeout
		manualUpdateCheckTimeout = oldManualTimeout
		if hadEnv {
			_ = os.Setenv("LEAKLENS_NO_UPDATE_CHECK", oldEnv)
		} else {
			_ = os.Unsetenv("LEAKLENS_NO_UPDATE_CHECK")
		}
	}
}
