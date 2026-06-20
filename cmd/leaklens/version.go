package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

// version is set at build time via -ldflags "-X main.version=..."
var version = "dev"

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Show version information",
	Long:  "Display the version of LeakLens",
	RunE:  runVersion,
}

func runVersion(cmd *cobra.Command, args []string) error {
	fmt.Fprintf(cmd.OutOrStdout(), "LeakLens %s\n", version)
	return nil
}
