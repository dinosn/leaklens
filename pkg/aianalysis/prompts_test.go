package aianalysis

import (
	"strings"
	"testing"
)

func TestChunkPromptRequiresEndpointPathPreservation(t *testing.T) {
	prompt := buildChunkPrompt(Config{Mode: ModeAll}, aiChunk{
		FileID:    "FILE_001",
		CloudPath: "TARGET_ORIGIN_1/static/app.js",
		LineRange: "lines 1-10",
		Text:      `fetch("TARGET_ORIGIN_1/api/files/upload"); fetch("/api/files/download?file_id=12345")`,
	})

	for _, want := range []string{
		"Endpoint preservation rule",
		"TARGET_ORIGIN_1/api/files/upload",
		"Visible endpoint/path hints",
		"`/api/files/download?file_id=12345`",
		"Do not output `TARGET_ORIGIN_1/REDACTED_UPLOAD_ENDPOINT`",
	} {
		if !strings.Contains(prompt, want) {
			t.Fatalf("chunk prompt missing %q:\n%s", want, prompt)
		}
	}
}

func TestSystemPromptForbidsInventedEndpointPlaceholders(t *testing.T) {
	prompt := buildSystemPrompt(Config{Mode: ModeAll})

	for _, want := range []string{
		"URL endpoint paths are intentionally preserved",
		"Never replace visible endpoint paths",
		"REDACTED_UPLOAD_ENDPOINT",
		"REDACTED_DOWNLOAD_ENDPOINT",
	} {
		if !strings.Contains(prompt, want) {
			t.Fatalf("system prompt missing %q:\n%s", want, prompt)
		}
	}
}
