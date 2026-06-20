package main

import (
	"github.com/spf13/cobra"
)

var (
	verbose bool
	quiet   bool
)

var rootCmd = &cobra.Command{
	Use:   "leaklens",
	Short: "LeakLens - web-aware secrets scanner",
	Long: `LeakLens is a fast secrets scanner that finds credentials in code, files, git history, and web application assets.
It uses regex-based detection rules to identify sensitive data like API keys, passwords, and tokens.`,
}

func init() {
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")
	rootCmd.PersistentFlags().BoolVarP(&quiet, "quiet", "q", false, "Quiet mode (errors only)")

	// Add subcommands
	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(githubCmd)
	rootCmd.AddCommand(rulesCmd)
	rootCmd.AddCommand(reportCmd)
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(gitlabCmd)
	rootCmd.AddCommand(exploreCmd)
}

// Execute runs the root command.
func Execute() error {
	return rootCmd.Execute()
}
