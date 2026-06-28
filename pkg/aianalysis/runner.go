package aianalysis

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const maxCloudPromptChars = 60000

func Run(ctx context.Context, cfg Config, files []CorpusFile) (Result, error) {
	if err := validateConfig(cfg); err != nil {
		return Result{}, err
	}
	now := time.Now
	if cfg.Now != nil {
		now = cfg.Now
	}
	if err := os.MkdirAll(cfg.ReportDir, 0755); err != nil {
		return Result{}, fmt.Errorf("creating AI report directory: %w", err)
	}

	progressPath := filepath.Join(cfg.ReportDir, "ai-progress.ndjson")
	progressFile, err := os.Create(progressPath)
	if err != nil {
		return Result{}, fmt.Errorf("creating AI progress log: %w", err)
	}
	defer progressFile.Close()
	progress := &progressWriter{human: cfg.Progress, ndjson: progressFile, now: now}

	progress.Emit("corpus", fmt.Sprintf("building AI corpus: %d candidate file(s)", len(files)), "", 0, len(files), nil)
	redactor := NewRedactor(cfg.CloudRedactionMode, cfg.TargetHints)
	prepared := prepareFiles(redactor, files)
	chunks := buildChunks(prepared)
	manifest := buildManifest(now(), cfg, prepared, chunks)

	manifestPath := filepath.Join(cfg.ReportDir, "corpus-manifest.json")
	if err := writeJSON(manifestPath, manifest); err != nil {
		return Result{}, err
	}
	redactionMapPath := filepath.Join(cfg.ReportDir, "ai-redaction-map.json")
	if err := writeJSON(redactionMapPath, redactor.Snapshot()); err != nil {
		return Result{}, err
	}

	reportPath := filepath.Join(cfg.ReportDir, "leaklens-ai-report.md")
	if len(prepared) == 0 {
		progress.Emit("report", "writing AI report: no supported JS/JSON files", "", 0, 0, nil)
		if err := writeNoFilesReport(reportPath, cfg, manifestPath, progressPath, redactionMapPath, now()); err != nil {
			return Result{}, err
		}
		return Result{ReportPath: reportPath, ManifestPath: manifestPath, ProgressPath: progressPath, RedactionMapPath: redactionMapPath, Provider: cfg.Provider, Model: cfg.Model}, nil
	}

	client, err := NewClient(cfg)
	if err != nil {
		return Result{}, err
	}

	systemPrompt := buildSystemPrompt(cfg)
	var sections []aiSection
	progress.Emit("overview", "requesting project-level AI overview", "", 0, 0, map[string]any{"chunks": len(chunks)})
	overviewPrompt := buildOverviewPrompt(cfg, prepared)
	overview, err := client.Complete(ctx, CompletionRequest{SystemPrompt: systemPrompt, UserPrompt: overviewPrompt})
	if err != nil {
		return Result{}, fmt.Errorf("AI project overview failed: %w", err)
	}
	sections = append(sections, aiSection{Title: "Project Overview", Body: overview.Text})

	for i, chunk := range chunks {
		progress.Emit("file-review", fmt.Sprintf("reviewing AI corpus chunk %d/%d", i+1, len(chunks)), chunk.FileID, i+1, len(chunks), map[string]any{"line_range": chunk.LineRange})
		resp, err := client.Complete(ctx, CompletionRequest{
			SystemPrompt: systemPrompt,
			UserPrompt:   buildChunkPrompt(cfg, chunk),
		})
		if err != nil {
			return Result{}, fmt.Errorf("AI chunk review failed for %s: %w", chunk.FileID, err)
		}
		sections = append(sections, aiSection{Title: "Review " + chunk.FileID + " " + chunk.LineRange, Body: resp.Text})
	}

	progress.Emit("report", "writing AI Markdown report", "", 0, 0, nil)
	if err := writeMarkdownReport(reportPath, cfg, manifest, sections, manifestPath, progressPath, redactionMapPath, now()); err != nil {
		return Result{}, err
	}
	progress.Emit("done", "AI analysis complete", "", len(prepared), len(prepared), map[string]any{"report": reportPath})

	return Result{
		ReportPath:       reportPath,
		ManifestPath:     manifestPath,
		ProgressPath:     progressPath,
		RedactionMapPath: redactionMapPath,
		FileCount:        len(prepared),
		ChunkCount:       len(chunks),
		Provider:         cfg.Provider,
		Model:            cfg.Model,
	}, nil
}

func validateConfig(cfg Config) error {
	if strings.TrimSpace(cfg.Provider) == "" {
		return fmt.Errorf("LEAKLENS_AI_PROVIDER is required when --ai is enabled")
	}
	if strings.TrimSpace(cfg.Model) == "" {
		return fmt.Errorf("LEAKLENS_AI_MODEL is required when --ai is enabled")
	}
	if strings.TrimSpace(cfg.APIKey) == "" {
		return fmt.Errorf("AI API key is required for provider %q", cfg.Provider)
	}
	switch cfg.Mode {
	case ModeSecrets, ModeAppSec, ModeAll:
	default:
		return fmt.Errorf("unsupported --ai-mode %q", cfg.Mode)
	}
	switch cfg.CloudRedactionMode {
	case CloudRedactionStandard, CloudRedactionExpanded:
	default:
		return fmt.Errorf("unsupported --ai-cloud-redaction %q", cfg.CloudRedactionMode)
	}
	if strings.TrimSpace(cfg.ReportDir) == "" {
		return fmt.Errorf("--ai-report-dir must not be empty when --ai is enabled")
	}
	return nil
}

type preparedFile struct {
	CorpusFile
	CloudPath       string
	CloudContent    string
	OriginalLineCnt int
}

type aiChunk struct {
	FileID    string
	CloudPath string
	LineRange string
	Text      string
}

func prepareFiles(redactor *Redactor, files []CorpusFile) []preparedFile {
	out := make([]preparedFile, 0, len(files))
	seen := make(map[string]bool)
	for _, file := range files {
		if !ShouldIncludePath(file.Path) {
			continue
		}
		key := file.BlobID + "\x00" + file.Path
		if seen[key] {
			continue
		}
		seen[key] = true
		content := string(file.Content)
		out = append(out, preparedFile{
			CorpusFile:      file,
			CloudPath:       redactor.RedactPath(file.Path),
			CloudContent:    redactor.RedactContent(content),
			OriginalLineCnt: countLines(content),
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].Path < out[j].Path
	})
	for i := range out {
		if out[i].ID == "" {
			out[i].ID = fmt.Sprintf("FILE_%03d", i+1)
		}
	}
	return out
}

func buildChunks(files []preparedFile) []aiChunk {
	var chunks []aiChunk
	for _, file := range files {
		lines := strings.SplitAfter(file.CloudContent, "\n")
		if len(lines) == 0 {
			lines = []string{file.CloudContent}
		}
		startLine := 1
		var b strings.Builder
		for idx, line := range lines {
			if b.Len()+len(line) > maxCloudPromptChars && b.Len() > 0 {
				endLine := idx
				chunks = append(chunks, aiChunk{
					FileID:    file.ID,
					CloudPath: file.CloudPath,
					LineRange: fmt.Sprintf("lines %d-%d", startLine, endLine),
					Text:      b.String(),
				})
				b.Reset()
				startLine = idx + 1
			}
			b.WriteString(line)
		}
		if b.Len() > 0 || len(lines) == 0 {
			chunks = append(chunks, aiChunk{
				FileID:    file.ID,
				CloudPath: file.CloudPath,
				LineRange: fmt.Sprintf("lines %d-%d", startLine, max(startLine, len(lines))),
				Text:      b.String(),
			})
		}
	}
	return chunks
}

func buildManifest(now time.Time, cfg Config, files []preparedFile, chunks []aiChunk) Manifest {
	chunkCounts := make(map[string]int)
	for _, chunk := range chunks {
		chunkCounts[chunk.FileID]++
	}
	manifest := Manifest{
		GeneratedAt:        now,
		Provider:           cfg.Provider,
		Model:              cfg.Model,
		Mode:               cfg.Mode,
		CloudRedactionMode: cfg.CloudRedactionMode,
		Files:              make([]ManifestFile, 0, len(files)),
	}
	for _, file := range files {
		manifest.Files = append(manifest.Files, ManifestFile{
			ID:          file.ID,
			Kind:        file.Kind,
			Path:        file.Path,
			CloudPath:   file.CloudPath,
			BlobID:      file.BlobID,
			Size:        file.Size,
			LineCount:   file.OriginalLineCnt,
			ChunkCount:  chunkCounts[file.ID],
			SentToCloud: true,
		})
	}
	return manifest
}

func ShouldIncludePath(path string) bool {
	ext := strings.ToLower(filepath.Ext(strings.Split(path, "?")[0]))
	switch ext {
	case ".js", ".mjs", ".cjs", ".json", ".map", ".jsx", ".ts", ".tsx":
		return true
	default:
		return false
	}
}

func writeJSON(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling %s: %w", path, err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	return nil
}

type progressWriter struct {
	human  io.Writer
	ndjson io.Writer
	now    func() time.Time
}

func (p *progressWriter) Emit(stage, message, fileID string, index, total int, extra map[string]any) {
	event := ProgressEvent{
		Time:    p.now(),
		Stage:   stage,
		Message: message,
		FileID:  fileID,
		Index:   index,
		Total:   total,
		Extra:   extra,
	}
	if p.human != nil {
		if total > 0 && index > 0 {
			fmt.Fprintf(p.human, "AI: %s (%d/%d)\n", message, index, total)
		} else {
			fmt.Fprintf(p.human, "AI: %s\n", message)
		}
	}
	if p.ndjson != nil {
		data, _ := json.Marshal(event)
		_, _ = p.ndjson.Write(append(data, '\n'))
	}
}

func countLines(text string) int {
	if text == "" {
		return 0
	}
	return strings.Count(text, "\n") + 1
}

func intString(value int) string {
	return fmt.Sprintf("%d", value)
}
