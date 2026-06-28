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
	"sync"
	"time"

	"golang.org/x/sync/errgroup"
)

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
	chunks := buildChunks(prepared, normalizedChunkChars(cfg.ChunkChars))
	manifest := buildManifest(now(), cfg, prepared, chunks)

	manifestPath := filepath.Join(cfg.ReportDir, "corpus-manifest.json")
	if err := writeJSON(manifestPath, manifest); err != nil {
		return Result{}, err
	}
	redactionMapPath := filepath.Join(cfg.ReportDir, "ai-redaction-map.json")
	if err := writeJSON(redactionMapPath, redactor.Snapshot()); err != nil {
		return Result{}, err
	}
	chunkDir := filepath.Join(cfg.ReportDir, "ai-chunks")
	if err := os.MkdirAll(chunkDir, 0755); err != nil {
		return Result{}, fmt.Errorf("creating AI chunk checkpoint directory: %w", err)
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
	var failures []aiFailure
	overviewCheckpoint := filepath.Join(chunkDir, "overview.md")
	if cfg.Resume {
		overviewText, ok, err := readCheckpoint(overviewCheckpoint)
		if err != nil {
			return Result{}, err
		}
		if ok {
			progress.Emit("overview", "reusing project-level AI overview checkpoint", "", 0, 0, map[string]any{"checkpoint": filepath.Base(overviewCheckpoint)})
			sections = append(sections, aiSection{Title: "Project Overview", Body: overviewText})
		}
	}
	if len(sections) == 0 {
		progress.Emit("overview", "requesting project-level AI overview", "", 0, 0, map[string]any{"chunks": len(chunks)})
		overviewPrompt := buildOverviewPrompt(cfg, prepared)
		overview, err := client.Complete(ctx, CompletionRequest{SystemPrompt: systemPrompt, UserPrompt: overviewPrompt})
		if err != nil {
			failures = append(failures, aiFailure{Stage: "overview", Error: err.Error()})
			progress.Emit("overview-failed", "project-level AI overview failed; continuing with file chunks", "", 0, 0, map[string]any{"error": err.Error()})
		} else {
			if err := writeCheckpoint(overviewCheckpoint, overview.Text); err != nil {
				return Result{}, err
			}
			sections = append(sections, aiSection{Title: "Project Overview", Body: overview.Text})
			if insights := extractLiveInsights(overview.Text); len(insights) > 0 {
				progress.Emit("overview-insight", "AI insight from project overview", "", 0, 0, map[string]any{"insights": insights})
			}
		}
	}

	concurrency := normalizedConcurrency(cfg.Concurrency, len(chunks))
	chunkSections, chunkFailures, completedChunks, err := reviewChunks(ctx, cfg, client, progress, systemPrompt, chunkDir, chunks, concurrency)
	if err != nil {
		return Result{}, err
	}
	failures = append(failures, chunkFailures...)
	for _, section := range chunkSections {
		if section.Body != "" {
			sections = append(sections, section)
		}
	}

	progress.Emit("report", "writing AI Markdown report", "", 0, 0, nil)
	if err := writeMarkdownReport(reportPath, cfg, manifest, sections, failures, manifestPath, progressPath, redactionMapPath, chunkDir, now()); err != nil {
		return Result{}, err
	}
	partial := len(failures) > 0
	doneMessage := "AI analysis complete"
	if partial {
		doneMessage = "AI analysis complete with partial results"
	}
	progress.Emit("done", doneMessage, "", completedChunks, len(chunks), map[string]any{"report": reportPath, "failed_chunks": countChunkFailures(failures)})

	return Result{
		ReportPath:       reportPath,
		ManifestPath:     manifestPath,
		ProgressPath:     progressPath,
		RedactionMapPath: redactionMapPath,
		FileCount:        len(prepared),
		ChunkCount:       len(chunks),
		CompletedChunks:  completedChunks,
		FailedChunks:     countChunkFailures(failures),
		Partial:          partial,
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

type aiFailure struct {
	Stage      string
	FileID     string
	LineRange  string
	ChunkIndex int
	Error      string
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

func buildChunks(files []preparedFile, maxCloudPromptChars int) []aiChunk {
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

func normalizedChunkChars(value int) int {
	if value > 0 {
		return value
	}
	return DefaultAIChunkChars
}

func normalizedConcurrency(value, chunkCount int) int {
	if chunkCount <= 0 {
		return 1
	}
	if value <= 0 {
		value = DefaultAIConcurrency
	}
	if value > chunkCount {
		return chunkCount
	}
	return value
}

func reviewChunks(ctx context.Context, cfg Config, client Client, progress *progressWriter, systemPrompt, chunkDir string, chunks []aiChunk, concurrency int) ([]aiSection, []aiFailure, int, error) {
	progress.Emit("file-review", fmt.Sprintf("reviewing AI corpus chunks with concurrency %d", concurrency), "", 0, len(chunks), map[string]any{"concurrency": concurrency})

	sections := make([]aiSection, len(chunks))
	completed := make([]bool, len(chunks))
	var failures []aiFailure
	completedCount := 0
	failedCount := 0
	var mu sync.Mutex

	markCompleted := func(index int) int {
		mu.Lock()
		completed[index] = true
		completedCount++
		processed := completedCount + failedCount
		mu.Unlock()
		return processed
	}
	recordFailure := func(failure aiFailure) (int, int) {
		mu.Lock()
		failures = append(failures, failure)
		failedCount++
		processed := completedCount + failedCount
		failed := failedCount
		mu.Unlock()
		return processed, failed
	}

	group, groupCtx := errgroup.WithContext(ctx)
	jobs := make(chan int)
	for worker := 0; worker < concurrency; worker++ {
		group.Go(func() error {
			for i := range jobs {
				chunk := chunks[i]
				checkpointPath := filepath.Join(chunkDir, chunkCheckpointName(i, chunk))
				if cfg.Resume {
					text, ok, err := readCheckpoint(checkpointPath)
					if err != nil {
						return err
					}
					if ok {
						sections[i] = aiSection{Title: "Review " + chunk.FileID + " " + chunk.LineRange, Body: text}
						processed := markCompleted(i)
						progress.Emit("file-review-done", fmt.Sprintf("reused AI corpus chunk %d from checkpoint", i+1), chunk.FileID, processed, len(chunks), map[string]any{"line_range": chunk.LineRange, "checkpoint": filepath.Base(checkpointPath), "chunk_index": i + 1, "progress_label": "processed"})
						continue
					}
				}
				resp, err := client.Complete(groupCtx, CompletionRequest{
					SystemPrompt: systemPrompt,
					UserPrompt:   buildChunkPrompt(cfg, chunk),
				})
				if err != nil {
					processed, failed := recordFailure(aiFailure{Stage: "file-review", FileID: chunk.FileID, LineRange: chunk.LineRange, ChunkIndex: i + 1, Error: err.Error()})
					progress.Emit("file-review-failed", fmt.Sprintf("failed AI corpus chunk %d; %d failed total", i+1, failed), chunk.FileID, processed, len(chunks), map[string]any{"line_range": chunk.LineRange, "error": err.Error(), "chunk_index": i + 1, "failed_chunks": failed, "progress_label": "processed"})
					continue
				}
				if err := writeCheckpoint(checkpointPath, resp.Text); err != nil {
					return err
				}
				sections[i] = aiSection{Title: "Review " + chunk.FileID + " " + chunk.LineRange, Body: resp.Text}
				processed := markCompleted(i)
				insights := extractLiveInsights(resp.Text)
				if len(insights) > 0 {
					progress.Emit("file-review-insight", fmt.Sprintf("AI insight from corpus chunk %d", i+1), chunk.FileID, 0, 0, map[string]any{"line_range": chunk.LineRange, "chunk_index": i + 1, "insights": insights})
				}
				progress.Emit("file-review-done", fmt.Sprintf("completed AI corpus chunk %d", i+1), chunk.FileID, processed, len(chunks), map[string]any{"line_range": chunk.LineRange, "chunk_index": i + 1, "progress_label": "processed"})
			}
			return nil
		})
	}

	for i := range chunks {
		chunk := chunks[i]
		select {
		case <-groupCtx.Done():
			close(jobs)
			if err := group.Wait(); err != nil {
				return nil, nil, 0, err
			}
			return nil, nil, 0, groupCtx.Err()
		case jobs <- i:
			progress.Emit("file-review-start", fmt.Sprintf("started AI corpus chunk %d/%d", i+1, len(chunks)), chunk.FileID, i+1, len(chunks), map[string]any{"line_range": chunk.LineRange, "chunk_index": i + 1, "suppress_human_progress": true})
		}
	}
	close(jobs)
	if err := group.Wait(); err != nil {
		return nil, nil, 0, err
	}

	sort.SliceStable(failures, func(i, j int) bool {
		return failures[i].ChunkIndex < failures[j].ChunkIndex
	})
	finalCompletedCount := 0
	for _, ok := range completed {
		if ok {
			finalCompletedCount++
		}
	}
	return sections, failures, finalCompletedCount, nil
}

func chunkCheckpointName(index int, chunk aiChunk) string {
	return fmt.Sprintf("chunk_%04d_%s.md", index+1, sanitizeCloudPathSegment(chunk.FileID))
}

func readCheckpoint(path string) (string, bool, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		return string(data), true, nil
	}
	if os.IsNotExist(err) {
		return "", false, nil
	}
	return "", false, fmt.Errorf("reading AI checkpoint %s: %w", path, err)
}

func writeCheckpoint(path, text string) error {
	text = strings.TrimSpace(text) + "\n"
	if err := os.WriteFile(path, []byte(text), 0644); err != nil {
		return fmt.Errorf("writing AI checkpoint %s: %w", path, err)
	}
	return nil
}

func countChunkFailures(failures []aiFailure) int {
	count := 0
	for _, failure := range failures {
		if failure.Stage == "file-review" {
			count++
		}
	}
	return count
}

func extractLiveInsights(text string) []string {
	const maxInsights = 3
	var insights []string
	seen := make(map[string]bool)
	for _, line := range strings.Split(text, "\n") {
		candidate := cleanInsightLine(line)
		if candidate == "" || seen[candidate] || !isSignificantInsight(candidate) {
			continue
		}
		seen[candidate] = true
		insights = append(insights, candidate)
		if len(insights) == maxInsights {
			return insights
		}
	}
	return insights
}

func cleanInsightLine(line string) string {
	line = strings.TrimSpace(line)
	line = strings.Trim(line, "|")
	line = strings.TrimSpace(line)
	line = strings.TrimLeft(line, "-*•0123456789. ")
	line = strings.Trim(line, "`")
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "---") || strings.HasPrefix(line, "```") {
		return ""
	}
	if len(line) > 220 {
		line = strings.TrimSpace(line[:220]) + "..."
	}
	return line
}

func isSignificantInsight(line string) bool {
	lower := strings.ToLower(line)
	if strings.Contains(lower, "none found") ||
		strings.Contains(lower, "no findings") ||
		strings.Contains(lower, "no secret") ||
		strings.Contains(lower, "no obvious") ||
		strings.Contains(lower, "not enough evidence") ||
		strings.Contains(lower, "not observed") {
		return false
	}
	keywords := []string{
		"api key", "secret", "token", "credential", "password", "authorization", "auth", "unauth",
		"cors", "debug", "misconfig", "vulnerab", "exposed", "leak", "admin", "risk", "critical", "high confidence",
	}
	for _, keyword := range keywords {
		if strings.Contains(lower, keyword) {
			return true
		}
	}
	return false
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
	mu     sync.Mutex
	human  io.Writer
	ndjson io.Writer
	now    func() time.Time
}

func (p *progressWriter) Emit(stage, message, fileID string, index, total int, extra map[string]any) {
	p.mu.Lock()
	defer p.mu.Unlock()
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
		if total > 0 && index > 0 && !extraBool(extra, "suppress_human_progress") {
			label := extraString(extra, "progress_label")
			if label != "" {
				fmt.Fprintf(p.human, "AI: %s (%d/%d %s)\n", message, index, total, label)
			} else {
				fmt.Fprintf(p.human, "AI: %s (%d/%d)\n", message, index, total)
			}
		} else {
			fmt.Fprintf(p.human, "AI: %s\n", message)
		}
		for _, insight := range extraStringSlice(extra, "insights") {
			fmt.Fprintf(p.human, "AI insight: %s\n", insight)
		}
	}
	if p.ndjson != nil {
		data, _ := json.Marshal(event)
		_, _ = p.ndjson.Write(append(data, '\n'))
	}
}

func extraBool(extra map[string]any, key string) bool {
	if extra == nil {
		return false
	}
	value, ok := extra[key].(bool)
	return ok && value
}

func extraString(extra map[string]any, key string) string {
	if extra == nil {
		return ""
	}
	value, ok := extra[key].(string)
	if !ok {
		return ""
	}
	return value
}

func extraStringSlice(extra map[string]any, key string) []string {
	if extra == nil {
		return nil
	}
	switch value := extra[key].(type) {
	case []string:
		return value
	case []any:
		out := make([]string, 0, len(value))
		for _, item := range value {
			if text, ok := item.(string); ok {
				out = append(out, text)
			}
		}
		return out
	default:
		return nil
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
