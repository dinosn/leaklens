package main

import (
	"bytes"
	"runtime/debug"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRunVersion(t *testing.T) {
	oldVersion := version
	version = "dev"
	t.Cleanup(func() {
		version = oldVersion
	})

	// Create a buffer to capture output
	var buf bytes.Buffer

	// Create a test command with our buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&buf)

	// Execute version command
	err := runVersion(cmd, []string{})
	require.NoError(t, err)

	// Verify output contains version info
	output := buf.String()
	assert.Contains(t, output, "LeakLens")
	assert.NotEqual(t, "LeakLens dev\n", output)
	assert.NotEmpty(t, strings.TrimSpace(output))
}

func TestResolvedVersionHonorsLdflagsVersion(t *testing.T) {
	oldVersion := version
	version = "v1.2.3"
	t.Cleanup(func() {
		version = oldVersion
	})

	assert.Equal(t, "v1.2.3", resolvedVersion())
}

func TestNormalizeModuleVersion(t *testing.T) {
	assert.Equal(t, "", normalizeModuleVersion(""))
	assert.Equal(t, "", normalizeModuleVersion("(devel)"))
	assert.Equal(t, "v0.0.0-20260622171402-364265e4cc6b", normalizeModuleVersion("v0.0.0-20260622171402-364265e4cc6b"))
}

func TestDisplayVersionLabelFormatsPseudoVersionAsMainRef(t *testing.T) {
	assert.Equal(t, "main@364265e4cc6b", displayVersionLabel("v0.0.0-20260622171402-364265e4cc6b", ""))
	assert.Equal(t, "main@364265e4cc6b", displayVersionLabel("v0.2.2-0.20260622171402-364265e4cc6b", ""))
	assert.Equal(t, "v0.2.0", displayVersionLabel("v0.2.0", "364265e4cc6b92b9d1fafbfb936a97484fc1052"))
	assert.Equal(t, "source", displayVersionLabel("source", "364265e4cc6b92b9d1fafbfb936a97484fc1052"))
}

func TestVersionDetails(t *testing.T) {
	details := versionDetails([]debug.BuildSetting{
		{Key: "vcs.revision", Value: "364265e4cc6b92b9d1fafbfb936a97484fc1052"},
		{Key: "vcs.time", Value: "2026-06-22T17:14:02Z"},
		{Key: "vcs.modified", Value: "true"},
	})

	assert.Equal(t, []string{"commit 364265e4cc6b", "2026-06-22T17:14:02Z", "modified"}, details)
}

func TestVersionCommandHasVerAlias(t *testing.T) {
	assert.Contains(t, versionCmd.Aliases, "ver")
}
