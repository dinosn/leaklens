package main

import (
	"bytes"
	"os"
	"testing"

	"github.com/dinosn/leaklens/pkg/enum"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRootCommandSuppressesUsageOnRuntimeError(t *testing.T) {
	restore := setRootGlobalsForTest()
	t.Cleanup(restore)

	var out bytes.Buffer
	var errOut bytes.Buffer
	var enumErr bytes.Buffer
	restoreLogs := enum.SetLogOutput(&enumErr)
	t.Cleanup(restoreLogs)

	rootCmd.SetOut(&out)
	rootCmd.SetErr(&errOut)
	rootCmd.SetArgs([]string{
		"--no-update-check",
		"scan",
		"--output",
		":memory:",
		"http://127.0.0.1:1/leaklens-missing.js",
	})

	err := rootCmd.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "all URL fetches failed")
	assert.NotContains(t, errOut.String(), "Usage:")
	assert.NotContains(t, out.String(), "Usage:")
}

func setRootGlobalsForTest() func() {
	oldVerbose := verbose
	oldQuiet := quiet
	oldUpdateCheckDisabled := updateCheckDisabled
	oldScanOutputPath := scanOutputPath

	return func() {
		verbose = oldVerbose
		quiet = oldQuiet
		updateCheckDisabled = oldUpdateCheckDisabled
		scanOutputPath = oldScanOutputPath

		rootCmd.SetArgs(nil)
		rootCmd.SetOut(os.Stdout)
		rootCmd.SetErr(os.Stderr)

		if flag := rootCmd.PersistentFlags().Lookup("no-update-check"); flag != nil {
			flag.Changed = false
		}
		if flag := scanCmd.Flags().Lookup("output"); flag != nil {
			flag.Changed = false
		}
	}
}
