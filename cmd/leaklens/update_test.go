package main

import (
	"bytes"
	"context"
	"io"
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
		_, _ = w.Write([]byte(`{"sha":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","html_url":"https://github.com/dinosn/leaklens/commit/bbbbbbbbbbbb"}`))
	}))
	defer server.Close()

	status, err := checkForUpdates(t.Context(), server.Client(), server.URL, buildIdentity{
		Version:  "v0.1.0",
		Revision: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	})
	require.NoError(t, err)
	assert.Equal(t, updateStateOutdated, status.State)
	assert.Equal(t, "v0.1.0", status.Current)
	assert.Equal(t, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", status.CurrentRevision)
	assert.Equal(t, "bbbbbbbbbbbb", status.Latest)
	assert.Equal(t, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", status.LatestRevision)
	assert.Equal(t, "main", status.InstallRef)
}

func TestCheckForUpdates_Latest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`))
	}))
	defer server.Close()

	status, err := checkForUpdates(t.Context(), server.Client(), server.URL, buildIdentity{
		Version:  "v0.1.1-0.20260623064508-aaaaaaaaaaaa",
		Revision: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	})
	require.NoError(t, err)
	assert.Equal(t, updateStateLatest, status.State)
}

func TestCheckForUpdates_ResolvesTaggedCurrentVersion(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/commits/main":
			_, _ = w.Write([]byte(`{"sha":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","html_url":"https://example.test/main"}`))
		case "/commits/v0.2.0":
			_, _ = w.Write([]byte(`{"sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","html_url":"https://example.test/v0.2.0"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	status, err := checkForUpdates(t.Context(), server.Client(), server.URL+"/commits/main", buildIdentity{
		Version: "v0.2.0",
	})
	require.NoError(t, err)
	assert.Equal(t, updateStateOutdated, status.State)
	assert.Equal(t, "v0.2.0", status.Current)
	assert.Equal(t, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", status.CurrentRevision)
	assert.Equal(t, "bbbbbbbbbbbb", status.Latest)
}

func TestCheckForUpdates_ResolvedTaggedCurrentVersionCanBeLatest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/commits/main", "/commits/v0.2.3":
			_, _ = w.Write([]byte(`{"sha":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	status, err := checkForUpdates(t.Context(), server.Client(), server.URL+"/commits/main", buildIdentity{
		Version: "v0.2.3",
	})
	require.NoError(t, err)
	assert.Equal(t, updateStateLatest, status.State)
	assert.Equal(t, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", status.CurrentRevision)
}

func TestCheckForUpdates_UnknownWhenMainUnavailable(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	defer server.Close()

	status, err := checkForUpdates(t.Context(), server.Client(), server.URL, buildIdentity{Version: "source"})
	require.NoError(t, err)
	assert.Equal(t, updateStateUnknown, status.State)
	assert.Equal(t, "source", status.Current)
}

func TestCommitEndpointForRef(t *testing.T) {
	assert.Equal(t,
		"https://api.github.com/repos/dinosn/leaklens/commits/v0.2.3",
		commitEndpointForRef("https://api.github.com/repos/dinosn/leaklens/commits/main", "v0.2.3"),
	)
	assert.Equal(t,
		"https://example.test/update/v0.2.3",
		commitEndpointForRef("https://example.test/update", "v0.2.3"),
	)
}

func TestClassifyUpdateStatus_PseudoVersionAgainstMain(t *testing.T) {
	status, err := classifyUpdateStatus(buildIdentity{
		Version: "v0.1.1-0.20260623064508-b975a091e833",
	}, "b975a091e8338e995ed7b9152b2517d1b07c8e0f", "")
	require.NoError(t, err)
	assert.Equal(t, updateStateLatest, status.State)
	assert.Equal(t, "b975a091e833", status.CurrentRevision)

	status, err = classifyUpdateStatus(buildIdentity{
		Version: "v0.1.1-0.20260623064508-b975a091e833",
	}, "a947838adc01eafc6a0db600865947cd324aeaaa", "")
	require.NoError(t, err)
	assert.Equal(t, updateStateOutdated, status.State)

	status, err = classifyUpdateStatus(buildIdentity{Version: "v0.1.0"}, "a947838adc01eafc6a0db600865947cd324aeaaa", "")
	require.NoError(t, err)
	assert.Equal(t, updateStateUnknown, status.State)
}

func TestPrintUpdateStatus_Outdated(t *testing.T) {
	oldInstallCommand := updateInstallCommand
	updateInstallCommand = func() string {
		return updateInstallCommandForBuild(false)
	}
	defer func() {
		updateInstallCommand = oldInstallCommand
	}()

	cmd := &cobra.Command{}
	var errOut bytes.Buffer
	cmd.SetErr(&errOut)

	printUpdateStatus(cmd, updateStatus{
		State:           updateStateOutdated,
		Current:         "v0.1.0",
		CurrentRevision: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Latest:          "bbbbbbbbbbbb",
		LatestURL:       "https://example.test/main",
		InstallRef:      "main",
	}, false)

	output := errOut.String()
	assert.Contains(t, output, "LeakLens main update available: v0.1.0 (aaaaaaaaaaaa) -> bbbbbbbbbbbb")
	assert.Contains(t, output, "GOPROXY=direct go install github.com/dinosn/leaklens/cmd/leaklens@main")
}

func TestUpdateCurrentLabelFormatsPseudoVersionAsMainRef(t *testing.T) {
	assert.Equal(t, "main@aaaaaaaaaaaa", updateCurrentLabel(updateStatus{
		Current:         "v0.2.3-0.20260623064508-aaaaaaaaaaaa",
		CurrentRevision: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}))
	assert.Equal(t, "v0.2.0 (aaaaaaaaaaaa)", updateCurrentLabel(updateStatus{
		Current:         "v0.2.0",
		CurrentRevision: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}))
}

func TestUpdateInstallCommandForBuild_Vectorscan(t *testing.T) {
	assert.Equal(t,
		"GOPROXY=direct CGO_ENABLED=1 go install -tags vectorscan github.com/dinosn/leaklens/cmd/leaklens@main",
		updateInstallCommandForBuild(true),
	)
	assert.Equal(t,
		"GOPROXY=direct go install github.com/dinosn/leaklens/cmd/leaklens@main",
		updateInstallCommandForBuild(false),
	)
}

func TestRunUpdateInstall_OutdatedRunsInstallCommand(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"sha":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","html_url":"https://example.test/main"}`))
	}))
	defer server.Close()

	restore := setUpdateGlobalsForTest(t)
	defer restore()
	version = "v0.1.1-0.20260623064508-aaaaaaaaaaaa"
	updateCheckURL = server.URL
	manualUpdateCheckTimeout = time.Second
	updateInstall = true

	var gotSpec updateInstallSpec
	updateInstallRunner = func(ctx context.Context, spec updateInstallSpec, stdout, stderr io.Writer) error {
		gotSpec = spec
		return nil
	}

	var out bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&out)

	require.NoError(t, runUpdate(cmd, nil))
	expectedSpec := currentUpdateInstallSpec()
	assert.Equal(t, expectedSpec, gotSpec)
	assert.Contains(t, out.String(), "Running: "+expectedSpec.String())
	assert.Contains(t, out.String(), "LeakLens update installed.")
}

func TestRunUpdateInstall_TaggedVersionRunsInstallCommand(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/commits/main":
			_, _ = w.Write([]byte(`{"sha":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","html_url":"https://example.test/main"}`))
		case "/commits/v0.2.0":
			_, _ = w.Write([]byte(`{"sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","html_url":"https://example.test/v0.2.0"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	restore := setUpdateGlobalsForTest(t)
	defer restore()
	version = "v0.2.0"
	updateCheckURL = server.URL + "/commits/main"
	manualUpdateCheckTimeout = time.Second
	updateInstall = true

	var gotSpec updateInstallSpec
	updateInstallRunner = func(ctx context.Context, spec updateInstallSpec, stdout, stderr io.Writer) error {
		gotSpec = spec
		return nil
	}

	var out bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&out)

	require.NoError(t, runUpdate(cmd, nil))
	expectedSpec := currentUpdateInstallSpec()
	assert.Equal(t, expectedSpec, gotSpec)
	assert.Contains(t, out.String(), "Running: "+expectedSpec.String())
	assert.Contains(t, out.String(), "LeakLens main update available: v0.2.0 (aaaaaaaaaaaa) -> bbbbbbbbbbbb")
	assert.Contains(t, out.String(), "LeakLens update installed.")
}

func TestRunUpdateInstall_LatestSkipsInstallCommand(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`))
	}))
	defer server.Close()

	restore := setUpdateGlobalsForTest(t)
	defer restore()
	version = "v0.1.1-0.20260623064508-aaaaaaaaaaaa"
	updateCheckURL = server.URL
	manualUpdateCheckTimeout = time.Second
	updateInstall = true

	ranInstall := false
	updateInstallRunner = func(ctx context.Context, spec updateInstallSpec, stdout, stderr io.Writer) error {
		ranInstall = true
		return nil
	}

	var out bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&out)

	require.NoError(t, runUpdate(cmd, nil))
	assert.False(t, ranInstall)
	assert.Contains(t, out.String(), "already on latest main")
}

func TestRunUpdate_UnknownWhenMainUnavailable(t *testing.T) {
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
	assert.Contains(t, out.String(), "LeakLens update status unknown:")
}

func TestRunUpdateInstall_UnknownReturnsError(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	defer server.Close()

	restore := setUpdateGlobalsForTest(t)
	defer restore()
	updateCheckURL = server.URL
	manualUpdateCheckTimeout = time.Second
	updateInstall = true

	var out bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&out)

	err := runUpdate(cmd, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "latest main status is unknown")
}

func TestNotifyUpdateStatus_PrintsLatestStatusOnStartup(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`))
	}))
	defer server.Close()

	restore := setUpdateGlobalsForTest(t)
	defer restore()
	version = "v0.1.1-0.20260623064508-aaaaaaaaaaaa"
	updateCheckURL = server.URL
	updateCheckTimeout = time.Second

	var errOut bytes.Buffer
	cmd := &cobra.Command{Use: "scan"}
	cmd.SetErr(&errOut)

	notifyUpdateStatus(cmd, nil)
	assert.Contains(t, errOut.String(), "LeakLens is on latest main: aaaaaaaaaaaa")
}

func TestNotifyUpdateStatus_SuppressesUnknownWithoutVerbose(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	defer server.Close()

	restore := setUpdateGlobalsForTest(t)
	defer restore()
	version = "v0.1.0"
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
	assert.True(t, shouldSkipUpdateCheck(versionCmd))
}

func TestShouldPrintStartupUpdateStatus(t *testing.T) {
	restore := setUpdateGlobalsForTest(t)
	defer restore()

	verbose = false
	assert.False(t, shouldPrintStartupUpdateStatus(updateStatus{State: updateStateUnknown}))
	assert.True(t, shouldPrintStartupUpdateStatus(updateStatus{State: updateStateLatest}))
	assert.True(t, shouldPrintStartupUpdateStatus(updateStatus{State: updateStateOutdated}))

	verbose = true
	assert.True(t, shouldPrintStartupUpdateStatus(updateStatus{State: updateStateUnknown}))
}

func TestUpdateCommandHasInstallFlag(t *testing.T) {
	assert.NotNil(t, updateCmd.Flags().Lookup("install"))
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
	oldInstallCommand := updateInstallCommand
	oldInstallRunner := updateInstallRunner
	oldInstall := updateInstall
	oldEnv, hadEnv := os.LookupEnv("LEAKLENS_NO_UPDATE_CHECK")

	quiet = false
	verbose = false
	updateCheckDisabled = false
	updateInstall = false
	_ = os.Unsetenv("LEAKLENS_NO_UPDATE_CHECK")

	return func() {
		version = oldVersion
		quiet = oldQuiet
		verbose = oldVerbose
		updateCheckDisabled = oldDisabled
		updateCheckURL = oldURL
		updateCheckTimeout = oldTimeout
		manualUpdateCheckTimeout = oldManualTimeout
		updateInstallCommand = oldInstallCommand
		updateInstallRunner = oldInstallRunner
		updateInstall = oldInstall
		if hadEnv {
			_ = os.Setenv("LEAKLENS_NO_UPDATE_CHECK", oldEnv)
		} else {
			_ = os.Unsetenv("LEAKLENS_NO_UPDATE_CHECK")
		}
	}
}
