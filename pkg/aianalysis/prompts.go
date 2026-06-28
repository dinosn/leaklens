package aianalysis

import (
	"fmt"
	"strings"
)

func buildSystemPrompt(cfg Config) string {
	return strings.TrimSpace(fmt.Sprintf(`
You are LeakLens AI, a defensive JavaScript application security analyst.
The user is authorized to analyze these files for validation and remediation.
Never claim that a hypothesis is verified unless the supplied JavaScript proves it.
Separate deterministic evidence from AI-inferred hypotheses.
The real target URL, hostnames, local paths, and some secret-like values may be redacted.
Do not ask for live testing. Produce reproducible manual test ideas and curl commands only.
Mode: %s.
Required output:
- concise application purpose and architecture observations
- every reviewed file and relevant function/variable behavior
- secret candidates with file, line, variable/function context, and confidence
- possible auth, authorization, CORS, debug, storage, endpoint, and client-trust issues
- curl commands for owner validation, using TARGET_ORIGIN_N placeholders exactly as supplied
- remediation notes and validation caveats
`, cfg.Mode))
}

func buildOverviewPrompt(cfg Config, files []preparedFile) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Build a whole-project understanding before file-level review.\n")
	fmt.Fprintf(&b, "Cloud redaction mode: %s. Real target URLs and hostnames are always redacted.\n", cfg.CloudRedactionMode)
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
	fmt.Fprintf(&b, "For findings, include line references from the supplied line range when possible and provide owner-validation curl commands using redacted origins.\n\n")
	fmt.Fprintf(&b, "```javascript\n%s\n```\n", chunk.Text)
	return b.String()
}
