package aianalysis

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type aiSection struct {
	Title string
	Body  string
}

func writeMarkdownReport(path string, cfg Config, manifest Manifest, sections []aiSection, manifestPath, progressPath, redactionMapPath string, now time.Time) error {
	var b strings.Builder
	writeReportHeader(&b, cfg, manifest, manifestPath, progressPath, redactionMapPath, now)
	b.WriteString("\n## AI Analysis\n\n")
	for _, section := range sections {
		fmt.Fprintf(&b, "### %s\n\n%s\n\n", section.Title, strings.TrimSpace(section.Body))
	}
	b.WriteString("## Notes\n\n")
	b.WriteString("- Curl commands in this report were generated as a validation plan and were not executed by LeakLens.\n")
	b.WriteString("- Findings marked as hypotheses require owner validation before remediation work is prioritized.\n")
	b.WriteString("- `TARGET_ORIGIN_N` and `EXTERNAL_ORIGIN_N` placeholders are mapped locally in `ai-redaction-map.json`.\n")
	return os.WriteFile(path, []byte(b.String()), 0644)
}

func writeNoFilesReport(path string, cfg Config, manifestPath, progressPath, redactionMapPath string, now time.Time) error {
	manifest := Manifest{
		GeneratedAt:        now,
		Provider:           cfg.Provider,
		Model:              cfg.Model,
		Mode:               cfg.Mode,
		CloudRedactionMode: cfg.CloudRedactionMode,
	}
	var b strings.Builder
	writeReportHeader(&b, cfg, manifest, manifestPath, progressPath, redactionMapPath, now)
	b.WriteString("\n## AI Analysis\n\nNo JavaScript, TypeScript, JSON, or source-map files were available for AI review.\n")
	return os.WriteFile(path, []byte(b.String()), 0644)
}

func writeReportHeader(b *strings.Builder, cfg Config, manifest Manifest, manifestPath, progressPath, redactionMapPath string, now time.Time) {
	b.WriteString("# LeakLens AI Analysis Report\n\n")
	fmt.Fprintf(b, "- Generated: %s\n", now.Format(time.RFC3339))
	fmt.Fprintf(b, "- Provider: %s\n", cfg.Provider)
	fmt.Fprintf(b, "- Model: %s\n", cfg.Model)
	fmt.Fprintf(b, "- Mode: %s\n", cfg.Mode)
	fmt.Fprintf(b, "- Cloud redaction mode: %s\n", cfg.CloudRedactionMode)
	b.WriteString("- Target URLs and hostnames sent to the provider: redacted always\n")
	if cfg.CloudRedactionMode == CloudRedactionStandard {
		b.WriteString("- Secret-like values sent to the provider: redacted by default\n")
	} else {
		b.WriteString("- Secret-like values sent to the provider: obvious credentials redacted; non-URL JS context preserved more aggressively\n")
	}
	fmt.Fprintf(b, "- Files reviewed by AI: %d\n", len(manifest.Files))
	fmt.Fprintf(b, "- Corpus manifest: `%s`\n", filepath.Base(manifestPath))
	fmt.Fprintf(b, "- Progress log: `%s`\n", filepath.Base(progressPath))
	fmt.Fprintf(b, "- Local redaction map: `%s`\n", filepath.Base(redactionMapPath))
	b.WriteString("\n## Coverage\n\n")
	b.WriteString("| File ID | Cloud path | Size | Lines | Chunks | Sent to cloud |\n")
	b.WriteString("| --- | --- | ---: | ---: | ---: | --- |\n")
	for _, file := range manifest.Files {
		fmt.Fprintf(b, "| `%s` | `%s` | %d | %d | %d | %t |\n", file.ID, escapeMarkdownPipes(file.CloudPath), file.Size, file.LineCount, file.ChunkCount, file.SentToCloud)
	}
}

func escapeMarkdownPipes(value string) string {
	return strings.ReplaceAll(value, "|", "\\|")
}
