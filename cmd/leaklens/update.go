package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/dinosn/leaklens/pkg/matcher"
	"github.com/spf13/cobra"
)

const defaultUpdateCheckURL = "https://api.github.com/repos/dinosn/leaklens/commits/main"

var (
	updateCheckURL           = defaultUpdateCheckURL
	updateCheckTimeout       = 1500 * time.Millisecond
	manualUpdateCheckTimeout = 10 * time.Second
	updateInstallCommand     = currentUpdateInstallCommand
	updateInstallRunner      = runUpdateInstallCommand
	updateInstall            bool
)

type updateState string

const (
	updateStateLatest   updateState = "latest"
	updateStateOutdated updateState = "outdated"
	updateStateUnknown  updateState = "unknown"
)

type buildIdentity struct {
	Version  string
	Revision string
}

type updateStatus struct {
	State           updateState
	Current         string
	CurrentRevision string
	Latest          string
	LatestRevision  string
	LatestURL       string
	InstallRef      string
}

type latestMainResponse struct {
	SHA     string `json:"sha"`
	HTMLURL string `json:"html_url"`
}

type updateInstallSpec struct {
	Env  []string
	Args []string
}

var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "Check for newer LeakLens main build",
	Long:  "Check whether this LeakLens binary matches the latest GitHub main branch commit.",
	RunE:  runUpdate,
}

func init() {
	updateCmd.Flags().BoolVar(&updateInstall, "install", false, "Install the latest main build after checking for updates")
}

func runUpdate(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(commandContext(cmd), manualUpdateCheckTimeout)
	defer cancel()

	status, err := checkForUpdates(ctx, http.DefaultClient, updateCheckURL, currentBuildIdentity())
	if err != nil {
		return err
	}
	printUpdateStatusTo(cmd.OutOrStdout(), status, true)
	if updateInstall {
		return installLatestMain(cmd, status)
	}
	return nil
}

func notifyUpdateStatus(cmd *cobra.Command, args []string) {
	if shouldSkipUpdateCheck(cmd) {
		return
	}

	ctx, cancel := context.WithTimeout(commandContext(cmd), updateCheckTimeout)
	defer cancel()

	status, err := checkForUpdates(ctx, http.DefaultClient, updateCheckURL, currentBuildIdentity())
	if err != nil {
		if verbose {
			fmt.Fprintf(cmd.ErrOrStderr(), "LeakLens update check unavailable: %v\n", err)
		}
		return
	}
	printUpdateStatus(cmd, status, shouldPrintStartupUpdateStatus(status))
}

func shouldSkipUpdateCheck(cmd *cobra.Command) bool {
	if quiet || updateCheckDisabled || updateCheckDisabledByEnv() {
		return true
	}
	if cmd == nil {
		return true
	}
	if cmd.CommandPath() == updateCmd.CommandPath() {
		return true
	}
	if cmd.CommandPath() == versionCmd.CommandPath() {
		return true
	}
	return false
}

func commandContext(cmd *cobra.Command) context.Context {
	if cmd == nil {
		return context.Background()
	}
	ctx := cmd.Context()
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

func updateCheckDisabledByEnv() bool {
	value := strings.TrimSpace(os.Getenv("LEAKLENS_NO_UPDATE_CHECK"))
	if value == "" {
		return false
	}
	disabled, err := strconv.ParseBool(value)
	if err != nil {
		return false
	}
	return disabled
}

func shouldPrintStartupUpdateStatus(status updateStatus) bool {
	if verbose {
		return true
	}
	return status.State != updateStateUnknown
}

func currentBuildIdentity() buildIdentity {
	return buildIdentity{
		Version:  currentVersionBase(),
		Revision: currentBuildRevision(),
	}
}

func currentBuildRevision() string {
	for _, setting := range currentBuildSettings() {
		if setting.Key == "vcs.revision" {
			return strings.TrimSpace(setting.Value)
		}
	}
	return ""
}

func checkForUpdates(ctx context.Context, client *http.Client, endpoint string, current buildIdentity) (updateStatus, error) {
	if client == nil {
		client = http.DefaultClient
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return updateStatus{}, fmt.Errorf("creating update request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "leaklens")

	resp, err := client.Do(req)
	if err != nil {
		return updateStatus{}, fmt.Errorf("fetching latest main commit: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return classifyUpdateStatus(current, "", "")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return updateStatus{}, fmt.Errorf("fetching latest main commit: HTTP %d", resp.StatusCode)
	}

	var latest latestMainResponse
	if err := json.NewDecoder(resp.Body).Decode(&latest); err != nil {
		return updateStatus{}, fmt.Errorf("decoding latest main commit: %w", err)
	}
	return classifyUpdateStatus(current, latest.SHA, strings.TrimSpace(latest.HTMLURL))
}

func normalizeCurrentVersion(current string) string {
	current = strings.TrimSpace(current)
	if current == "" {
		return "source"
	}
	return current
}

func classifyUpdateStatus(current buildIdentity, latestRevision, latestURL string) (updateStatus, error) {
	currentVersion := normalizeCurrentVersion(current.Version)
	currentRevision := resolveCurrentRevision(current)
	latestRevision = normalizeRevision(latestRevision)
	latest := shortRevision(latestRevision)
	if latest == "" {
		latest = "unknown"
	}

	status := updateStatus{
		Current:         currentVersion,
		CurrentRevision: currentRevision,
		Latest:          latest,
		LatestRevision:  latestRevision,
		LatestURL:       latestURL,
		InstallRef:      "main",
	}

	if latestRevision == "" || currentRevision == "" {
		status.State = updateStateUnknown
		return status, nil
	}

	if sameRevision(currentRevision, latestRevision) {
		status.State = updateStateLatest
		return status, nil
	}
	status.State = updateStateOutdated
	return status, nil
}

func resolveCurrentRevision(current buildIdentity) string {
	if revision := normalizeRevision(current.Revision); revision != "" {
		return revision
	}
	return pseudoVersionRevision(current.Version)
}

func pseudoVersionRevision(current string) string {
	parts := strings.Split(strings.TrimSpace(strings.TrimPrefix(current, "v")), "-")
	if len(parts) < 3 {
		return ""
	}

	timestamp := parts[len(parts)-2]
	if idx := strings.LastIndexByte(timestamp, '.'); idx >= 0 {
		timestamp = timestamp[idx+1:]
	}
	if len(timestamp) != 14 {
		return ""
	}
	for _, r := range timestamp {
		if r < '0' || r > '9' {
			return ""
		}
	}

	revision := normalizeRevision(parts[len(parts)-1])
	if len(revision) < 12 {
		return ""
	}
	return revision
}

func normalizeRevision(revision string) string {
	revision = strings.ToLower(strings.TrimSpace(revision))
	if revision == "" {
		return ""
	}
	for _, r := range revision {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return ""
		}
	}
	return revision
}

func sameRevision(current, latest string) bool {
	current = normalizeRevision(current)
	latest = normalizeRevision(latest)
	if current == "" || latest == "" {
		return false
	}
	if len(current) <= len(latest) {
		return strings.HasPrefix(latest, current)
	}
	return strings.HasPrefix(current, latest)
}

func updateCurrentLabel(status updateStatus) string {
	if pseudoVersionRevision(status.Current) != "" && status.CurrentRevision != "" {
		return "main@" + shortRevision(status.CurrentRevision)
	}
	if status.CurrentRevision == "" {
		return status.Current
	}
	return fmt.Sprintf("%s (%s)", status.Current, shortRevision(status.CurrentRevision))
}

func currentUpdateInstallCommand() string {
	return currentUpdateInstallSpec().String()
}

func updateInstallCommandForBuild(vectorscan bool) string {
	return updateInstallSpecForBuild(vectorscan).String()
}

func currentUpdateInstallSpec() updateInstallSpec {
	return updateInstallSpecForBuild(matcher.VectorscanAvailable())
}

func updateInstallSpecForBuild(vectorscan bool) updateInstallSpec {
	target := "github.com/dinosn/leaklens/cmd/leaklens@main"
	spec := updateInstallSpec{
		Env:  []string{"GOPROXY=direct"},
		Args: []string{"go", "install"},
	}
	if vectorscan {
		spec.Env = append(spec.Env, "CGO_ENABLED=1")
		spec.Args = append(spec.Args, "-tags", "vectorscan")
	}
	spec.Args = append(spec.Args, target)
	return spec
}

func (s updateInstallSpec) String() string {
	parts := make([]string, 0, len(s.Env)+len(s.Args))
	parts = append(parts, s.Env...)
	parts = append(parts, s.Args...)
	return strings.Join(parts, " ")
}

func installLatestMain(cmd *cobra.Command, status updateStatus) error {
	switch status.State {
	case updateStateLatest:
		fmt.Fprintln(cmd.OutOrStdout(), "LeakLens is already on latest main; no install needed.")
		return nil
	case updateStateUnknown:
		return fmt.Errorf("cannot install update: latest main status is unknown")
	}

	spec := currentUpdateInstallSpec()
	fmt.Fprintf(cmd.OutOrStdout(), "Running: %s\n", spec.String())
	if err := updateInstallRunner(commandContext(cmd), spec, cmd.OutOrStdout(), cmd.ErrOrStderr()); err != nil {
		return fmt.Errorf("installing latest main: %w", err)
	}
	fmt.Fprintln(cmd.OutOrStdout(), "LeakLens update installed.")
	return nil
}

func runUpdateInstallCommand(ctx context.Context, spec updateInstallSpec, stdout, stderr io.Writer) error {
	if len(spec.Args) == 0 {
		return fmt.Errorf("empty install command")
	}
	command := exec.CommandContext(ctx, spec.Args[0], spec.Args[1:]...)
	command.Env = append(os.Environ(), spec.Env...)
	command.Stdout = stdout
	command.Stderr = stderr
	return command.Run()
}

func printUpdateStatus(cmd *cobra.Command, status updateStatus, includeLatestStatus bool) {
	printUpdateStatusTo(cmd.ErrOrStderr(), status, includeLatestStatus)
}

func printUpdateStatusTo(out io.Writer, status updateStatus, includeLatestStatus bool) {
	switch status.State {
	case updateStateOutdated:
		fmt.Fprintf(out, "LeakLens main update available: %s -> %s\n", updateCurrentLabel(status), status.Latest)
		if status.LatestURL != "" {
			fmt.Fprintf(out, "Main: %s\n", status.LatestURL)
		}
		fmt.Fprintf(out, "Install: %s\n", updateInstallCommand())
	case updateStateLatest:
		if includeLatestStatus {
			fmt.Fprintf(out, "LeakLens is on latest main: %s\n", status.Latest)
		}
	case updateStateUnknown:
		if includeLatestStatus {
			fmt.Fprintf(out, "LeakLens update status unknown: current %s, latest main %s\n", updateCurrentLabel(status), status.Latest)
		}
	}
}
