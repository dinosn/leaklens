package aianalysis

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fakeClient struct {
	calls []CompletionRequest
}

func (f *fakeClient) Complete(ctx context.Context, req CompletionRequest) (CompletionResponse, error) {
	f.calls = append(f.calls, req)
	return CompletionResponse{Text: "AI section with curl -i 'TARGET_ORIGIN_1/api/test'"}, nil
}

func TestRunWritesArtifactsAndDoesNotSendTargetURL(t *testing.T) {
	client := &fakeClient{}
	reportDir := t.TempDir()
	cfg := Config{
		Provider:           "openai",
		Model:              "test-model",
		APIKey:             "test-key",
		Mode:               ModeAll,
		CloudRedactionMode: CloudRedactionStandard,
		ReportDir:          reportDir,
		TargetHints:        []string{"https://www.example.test/"},
		Client:             client,
		Now: func() time.Time {
			return time.Date(2026, 6, 28, 12, 0, 0, 0, time.UTC)
		},
	}
	files := []CorpusFile{{
		ID:      "FILE_001",
		Path:    "https://www.example.test/static/app.js",
		Kind:    "url",
		BlobID:  "abc123",
		Size:    len(`fetch("https://www.example.test/api/test"); const apiKey = "dummy_secret_value_for_redaction_tests";`),
		Content: []byte(`fetch("https://www.example.test/api/test"); const apiKey = "dummy_secret_value_for_redaction_tests";`),
	}}

	result, err := Run(context.Background(), cfg, files)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}

	for _, path := range []string{result.ReportPath, result.ManifestPath, result.ProgressPath, result.RedactionMapPath} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected artifact %s: %v", path, err)
		}
	}
	if len(client.calls) != 2 {
		t.Fatalf("expected overview and chunk calls, got %d", len(client.calls))
	}
	for _, call := range client.calls {
		if strings.Contains(call.UserPrompt, "example.test") {
			t.Fatalf("target hostname leaked to provider prompt: %s", call.UserPrompt)
		}
		if strings.Contains(call.UserPrompt, "dummy_secret_value_for_redaction_tests") {
			t.Fatalf("secret value leaked to provider prompt: %s", call.UserPrompt)
		}
	}

	report, err := os.ReadFile(filepath.Join(reportDir, "leaklens-ai-report.md"))
	if err != nil {
		t.Fatalf("reading report: %v", err)
	}
	if !strings.Contains(string(report), "Target URLs and hostnames sent to the provider: redacted always") {
		t.Fatalf("report does not document mandatory URL redaction:\n%s", string(report))
	}
}
