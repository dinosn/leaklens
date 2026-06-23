package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

const defaultUpdateCheckURL = "https://api.github.com/repos/dinosn/leaklens/releases/latest"

var (
	updateCheckURL           = defaultUpdateCheckURL
	updateCheckTimeout       = 1500 * time.Millisecond
	manualUpdateCheckTimeout = 10 * time.Second
)

type updateState string

const (
	updateStateLatest      updateState = "latest"
	updateStateOutdated    updateState = "outdated"
	updateStateDevelopment updateState = "development"
	updateStateNoRelease   updateState = "no_release"
	updateStateUnknown     updateState = "unknown"
)

type updateStatus struct {
	State      updateState
	Current    string
	Latest     string
	LatestURL  string
	InstallRef string
}

type latestReleaseResponse struct {
	TagName string `json:"tag_name"`
	HTMLURL string `json:"html_url"`
}

var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "Check for newer LeakLens release",
	Long:  "Check whether this LeakLens binary matches the latest published GitHub release.",
	RunE:  runUpdate,
}

func runUpdate(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(commandContext(cmd), manualUpdateCheckTimeout)
	defer cancel()

	status, err := checkForUpdates(ctx, http.DefaultClient, updateCheckURL, currentVersionBase())
	if err != nil {
		return err
	}
	printUpdateStatusTo(cmd.OutOrStdout(), status, true)
	return nil
}

func notifyUpdateStatus(cmd *cobra.Command, args []string) {
	if shouldSkipUpdateCheck(cmd) {
		return
	}

	ctx, cancel := context.WithTimeout(commandContext(cmd), updateCheckTimeout)
	defer cancel()

	status, err := checkForUpdates(ctx, http.DefaultClient, updateCheckURL, currentVersionBase())
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
	return status.State != updateStateNoRelease
}

func checkForUpdates(ctx context.Context, client *http.Client, endpoint, current string) (updateStatus, error) {
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
		return updateStatus{}, fmt.Errorf("fetching latest release: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return updateStatus{
			State:   updateStateNoRelease,
			Current: normalizeCurrentVersion(current),
		}, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return updateStatus{}, fmt.Errorf("fetching latest release: HTTP %d", resp.StatusCode)
	}

	var release latestReleaseResponse
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return updateStatus{}, fmt.Errorf("decoding latest release: %w", err)
	}
	latest := strings.TrimSpace(release.TagName)
	if latest == "" {
		return updateStatus{}, errors.New("latest release response did not include tag_name")
	}

	return classifyUpdateStatus(normalizeCurrentVersion(current), latest, strings.TrimSpace(release.HTMLURL)), nil
}

func normalizeCurrentVersion(current string) string {
	current = strings.TrimSpace(current)
	if current == "" {
		return "source"
	}
	return current
}

func classifyUpdateStatus(current, latest, latestURL string) updateStatus {
	status := updateStatus{
		Current:    current,
		Latest:     latest,
		LatestURL:  latestURL,
		InstallRef: latest,
	}

	if current == latest {
		status.State = updateStateLatest
		return status
	}

	if isDevelopmentVersion(current) {
		status.State = updateStateDevelopment
		return status
	}

	cmp, ok := compareReleaseVersions(current, latest)
	if !ok {
		status.State = updateStateUnknown
		return status
	}
	if cmp < 0 {
		status.State = updateStateOutdated
		return status
	}
	status.State = updateStateLatest
	return status
}

func isDevelopmentVersion(current string) bool {
	current = strings.TrimSpace(current)
	if current == "" || current == "source" || strings.HasPrefix(current, "commit ") {
		return true
	}
	if isGoPseudoVersion(current) {
		return true
	}
	return false
}

func isGoPseudoVersion(current string) bool {
	parts := strings.Split(strings.TrimPrefix(current, "v"), "-")
	if len(parts) < 3 {
		return false
	}

	timestamp := parts[len(parts)-2]
	if idx := strings.LastIndexByte(timestamp, '.'); idx >= 0 {
		timestamp = timestamp[idx+1:]
	}
	if len(timestamp) != 14 {
		return false
	}
	for _, r := range timestamp {
		if r < '0' || r > '9' {
			return false
		}
	}

	revision := parts[len(parts)-1]
	if len(revision) < 12 {
		return false
	}
	for _, r := range revision {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

func compareReleaseVersions(current, latest string) (int, bool) {
	currentVersion, ok := parseReleaseVersion(current)
	if !ok {
		return 0, false
	}
	latestVersion, ok := parseReleaseVersion(latest)
	if !ok {
		return 0, false
	}
	for i := range currentVersion {
		if currentVersion[i] < latestVersion[i] {
			return -1, true
		}
		if currentVersion[i] > latestVersion[i] {
			return 1, true
		}
	}
	return 0, true
}

func parseReleaseVersion(value string) ([3]int, bool) {
	value = strings.TrimSpace(strings.TrimPrefix(value, "v"))
	parts := strings.Split(value, ".")
	if len(parts) != 3 {
		return [3]int{}, false
	}

	var parsed [3]int
	for i, part := range parts {
		if idx := strings.IndexByte(part, '-'); idx >= 0 {
			part = part[:idx]
		}
		n, err := strconv.Atoi(part)
		if err != nil || n < 0 {
			return [3]int{}, false
		}
		parsed[i] = n
	}
	return parsed, true
}

func printUpdateStatus(cmd *cobra.Command, status updateStatus, includeLatestStatus bool) {
	printUpdateStatusTo(cmd.ErrOrStderr(), status, includeLatestStatus)
}

func printUpdateStatusTo(out io.Writer, status updateStatus, includeLatestStatus bool) {
	switch status.State {
	case updateStateOutdated:
		fmt.Fprintf(out, "LeakLens update available: %s -> %s\n", status.Current, status.Latest)
		if status.LatestURL != "" {
			fmt.Fprintf(out, "Release: %s\n", status.LatestURL)
		}
		fmt.Fprintf(out, "Install: GOPROXY=direct go install github.com/dinosn/leaklens/cmd/leaklens@%s\n", status.InstallRef)
	case updateStateLatest:
		if includeLatestStatus {
			fmt.Fprintf(out, "LeakLens is on the latest release: %s\n", status.Latest)
		}
	case updateStateDevelopment:
		if includeLatestStatus {
			fmt.Fprintf(out, "LeakLens is a development build (%s); latest release is %s\n", status.Current, status.Latest)
		}
	case updateStateNoRelease:
		if includeLatestStatus {
			fmt.Fprintf(out, "No GitHub release is published for LeakLens yet. Current build: %s\n", status.Current)
		}
	case updateStateUnknown:
		if includeLatestStatus {
			fmt.Fprintf(out, "LeakLens update status unknown: current %s, latest release %s\n", status.Current, status.Latest)
		}
	}
}
