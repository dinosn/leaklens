package aianalysis

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fakeClient struct {
	calls    []CompletionRequest
	failCall int
	failErr  error
}

func (f *fakeClient) Complete(ctx context.Context, req CompletionRequest) (CompletionResponse, error) {
	f.calls = append(f.calls, req)
	if f.failCall == len(f.calls) {
		return CompletionResponse{}, f.failErr
	}
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

func TestRunWritesPartialReportWhenChunkFails(t *testing.T) {
	client := &fakeClient{
		failCall: 2,
		failErr:  errors.New(`Post "https://api.openai.com/v1/responses": context deadline exceeded (Client.Timeout exceeded while awaiting headers)`),
	}
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
	}
	files := []CorpusFile{{
		ID:      "FILE_001",
		Path:    "https://www.example.test/static/app.js",
		Kind:    "url",
		BlobID:  "abc123",
		Size:    len(`fetch("https://www.example.test/api/test");`),
		Content: []byte(`fetch("https://www.example.test/api/test");`),
	}}

	result, err := Run(context.Background(), cfg, files)
	if err != nil {
		t.Fatalf("Run should return a partial report instead of failing: %v", err)
	}
	if !result.Partial {
		t.Fatalf("expected partial result: %#v", result)
	}
	if result.CompletedChunks != 0 || result.FailedChunks != 1 || result.ChunkCount != 1 {
		t.Fatalf("unexpected chunk counts: %#v", result)
	}
	report, err := os.ReadFile(result.ReportPath)
	if err != nil {
		t.Fatalf("reading report: %v", err)
	}
	reportText := string(report)
	for _, want := range []string{"AI status: partial", "## AI Failures", "context deadline exceeded", "--ai-resume"} {
		if !strings.Contains(reportText, want) {
			t.Fatalf("report missing %q:\n%s", want, reportText)
		}
	}
}

func TestRunResumeUsesCompletedCheckpoints(t *testing.T) {
	client := &fakeClient{}
	reportDir := t.TempDir()
	chunkDir := filepath.Join(reportDir, "ai-chunks")
	if err := os.MkdirAll(chunkDir, 0755); err != nil {
		t.Fatalf("creating checkpoint dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(chunkDir, "overview.md"), []byte("overview from checkpoint\n"), 0644); err != nil {
		t.Fatalf("writing overview checkpoint: %v", err)
	}
	if err := os.WriteFile(filepath.Join(chunkDir, "chunk_0001_FILE_001.md"), []byte("chunk from checkpoint\n"), 0644); err != nil {
		t.Fatalf("writing chunk checkpoint: %v", err)
	}
	cfg := Config{
		Provider:           "openai",
		Model:              "test-model",
		APIKey:             "test-key",
		Mode:               ModeAll,
		CloudRedactionMode: CloudRedactionStandard,
		ReportDir:          reportDir,
		TargetHints:        []string{"https://www.example.test/"},
		Client:             client,
		Resume:             true,
	}
	files := []CorpusFile{{
		ID:      "FILE_001",
		Path:    "https://www.example.test/static/app.js",
		Kind:    "url",
		BlobID:  "abc123",
		Size:    len(`fetch("https://www.example.test/api/test");`),
		Content: []byte(`fetch("https://www.example.test/api/test");`),
	}}

	result, err := Run(context.Background(), cfg, files)
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if len(client.calls) != 0 {
		t.Fatalf("expected checkpoints to avoid AI calls, got %d", len(client.calls))
	}
	if result.Partial || result.CompletedChunks != 1 || result.FailedChunks != 0 {
		t.Fatalf("unexpected result: %#v", result)
	}
	report, err := os.ReadFile(result.ReportPath)
	if err != nil {
		t.Fatalf("reading report: %v", err)
	}
	if !strings.Contains(string(report), "chunk from checkpoint") {
		t.Fatalf("report did not use checkpoint body:\n%s", string(report))
	}
}
