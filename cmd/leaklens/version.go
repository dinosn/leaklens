package main

import (
	"fmt"
	"runtime/debug"
	"strings"

	"github.com/spf13/cobra"
)

// version is set at build time via -ldflags "-X main.version=..."
var version = "dev"

var versionCmd = &cobra.Command{
	Use:     "version",
	Aliases: []string{"ver"},
	Short:   "Show version information",
	Long:    "Display the version of LeakLens",
	RunE:    runVersion,
}

func runVersion(cmd *cobra.Command, args []string) error {
	fmt.Fprintf(cmd.OutOrStdout(), "LeakLens %s\n", resolvedVersion())
	return nil
}

func resolvedVersion() string {
	buildVersion := strings.TrimSpace(version)
	if buildVersion != "" && buildVersion != "dev" {
		return buildVersion
	}

	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "source"
	}

	moduleVersion := normalizeModuleVersion(info.Main.Version)
	if moduleVersion == "" {
		moduleVersion = "source"
	}

	details := versionDetails(info.Settings)
	if len(details) == 0 {
		return moduleVersion
	}

	return fmt.Sprintf("%s (%s)", moduleVersion, strings.Join(details, ", "))
}

func normalizeModuleVersion(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || value == "(devel)" {
		return ""
	}
	return value
}

func versionDetails(settings []debug.BuildSetting) []string {
	values := make(map[string]string, len(settings))
	for _, setting := range settings {
		values[setting.Key] = setting.Value
	}

	var details []string
	if revision := values["vcs.revision"]; revision != "" {
		details = append(details, "commit "+shortRevision(revision))
	}
	if vcsTime := values["vcs.time"]; vcsTime != "" {
		details = append(details, vcsTime)
	}
	if values["vcs.modified"] == "true" {
		details = append(details, "modified")
	}
	return details
}

func shortRevision(revision string) string {
	if len(revision) <= 12 {
		return revision
	}
	return revision[:12]
}
