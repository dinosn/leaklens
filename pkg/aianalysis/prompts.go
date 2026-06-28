package aianalysis

import (
	"fmt"
	"regexp"
	"strings"
)

var (
	redactedEndpointHintPattern = regexp.MustCompile(`\b(?:TARGET_ORIGIN|EXTERNAL_ORIGIN)_\d+(?:/[A-Za-z0-9._~!$&'()*+,;=:@%/-]*)?(?:\?[A-Za-z0-9._~!$&'()*+,;=:@%/?-]*)?`)
	relativeEndpointHintPattern = regexp.MustCompile(`["'\x60](/[A-Za-z0-9][A-Za-z0-9._~!$&'()*+,;=:@%/-]*(?:\?[A-Za-z0-9._~!$&'()*+,;=:@%/?-]*)?)["'\x60]`)
)

func buildSystemPrompt(cfg Config) string {
	return strings.TrimSpace(fmt.Sprintf(`
You are LeakLens AI, a defensive JavaScript application security analyst.
The user is authorized to analyze these files for validation and remediation.
Never claim that a hypothesis is verified unless the supplied JavaScript proves it.
Separate deterministic evidence from AI-inferred hypotheses.
Real target origins/hostnames and local filesystem paths may be redacted.
URL endpoint paths are intentionally preserved after origin placeholders. Keep paths exactly as supplied.
Never replace visible endpoint paths with REDACTED_ENDPOINT, REDACTED_UPLOAD_ENDPOINT, REDACTED_DOWNLOAD_ENDPOINT, or similar generic placeholders.
If an endpoint path is not visible in the supplied JavaScript, say the path is not visible instead of inventing a redacted path.
Do not ask for live testing. Produce reproducible manual test ideas and curl commands only.
Mode: %s.
Required output:
- concise application purpose and architecture observations
- every reviewed file and relevant function/variable behavior
- secret candidates with file, line, variable/function context, and confidence
- possible auth, authorization, CORS, debug, storage, endpoint, and client-trust issues
- put high-priority findings near the top of each chunk response so they can be surfaced while the run is still active
- curl commands for owner validation, using TARGET_ORIGIN_N placeholders and the exact visible URL paths/query parameter names supplied
- remediation notes and validation caveats
`, cfg.Mode))
}

func buildOverviewPrompt(cfg Config, files []preparedFile) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Build a whole-project understanding before file-level review.\n")
	fmt.Fprintf(&b, "Cloud redaction mode: %s. Real target origins and hostnames are always redacted, but URL endpoint paths are preserved after placeholders such as TARGET_ORIGIN_1.\n", cfg.CloudRedactionMode)
	fmt.Fprintf(&b, "Files in corpus: %d\n\n", len(files))
	for _, file := range files {
		fmt.Fprintf(&b, "- %s: %s (%d bytes, %d lines)\n", file.ID, file.CloudPath, file.Size, file.OriginalLineCnt)
	}
	fmt.Fprintf(&b, "\nReturn an overview of likely application purpose, main data flows, authentication clues, API surface, third-party integrations, and highest-priority areas for deep review.\n")
	return b.String()
}

func buildChunkPrompt(cfg Config, chunk aiChunk) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Review this JavaScript/JSON corpus chunk deeply.\n")
	fmt.Fprintf(&b, "File ID: %s\n", chunk.FileID)
	fmt.Fprintf(&b, "Cloud path: %s\n", chunk.CloudPath)
	fmt.Fprintf(&b, "Line range: %s\n", chunk.LineRange)
	fmt.Fprintf(&b, "Mode: %s\n\n", cfg.Mode)
	fmt.Fprintf(&b, "Check every function, variable, endpoint, storage access, auth check, config value, and secret-like value visible in this chunk. Do not skip the file.\n")
	fmt.Fprintf(&b, "For findings, include line references from the supplied line range when possible and provide owner-validation curl commands using redacted origins.\n")
	fmt.Fprintf(&b, "Endpoint preservation rule: if the chunk contains `TARGET_ORIGIN_1/api/files/upload`, output curl commands with `TARGET_ORIGIN_1/api/files/upload` exactly. Do not output `TARGET_ORIGIN_1/REDACTED_UPLOAD_ENDPOINT` or any other invented endpoint placeholder.\n\n")
	if endpoints := extractEndpointHints(chunk.Text); len(endpoints) > 0 {
		fmt.Fprintf(&b, "Visible endpoint/path hints to copy exactly when relevant:\n")
		for _, endpoint := range endpoints {
			fmt.Fprintf(&b, "- `%s`\n", endpoint)
		}
		fmt.Fprintf(&b, "\n")
	}
	fmt.Fprintf(&b, "```javascript\n%s\n```\n", chunk.Text)
	return b.String()
}

func extractEndpointHints(text string) []string {
	const maxEndpointHints = 30
	seen := make(map[string]bool)
	var endpoints []string
	add := func(endpoint string) {
		endpoint = strings.TrimSpace(endpoint)
		if endpoint == "" || seen[endpoint] {
			return
		}
		seen[endpoint] = true
		endpoints = append(endpoints, endpoint)
	}
	for _, match := range redactedEndpointHintPattern.FindAllString(text, -1) {
		add(match)
		if len(endpoints) == maxEndpointHints {
			return endpoints
		}
	}
	for _, match := range relativeEndpointHintPattern.FindAllStringSubmatch(text, -1) {
		if len(match) > 1 {
			add(match[1])
		}
		if len(endpoints) == maxEndpointHints {
			return endpoints
		}
	}
	return endpoints
}
