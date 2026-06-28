package aianalysis

import (
	"context"
	"io"
	"net/http"
	"time"
)

type Mode string

const (
	ModeSecrets Mode = "secrets"
	ModeAppSec  Mode = "appsec"
	ModeAll     Mode = "all"
)

type CloudRedactionMode string

const (
	CloudRedactionStandard CloudRedactionMode = "standard"
	CloudRedactionExpanded CloudRedactionMode = "expanded"
)

const (
	DefaultAITimeout    = 5 * time.Minute
	DefaultAIRetries    = 3
	DefaultAIChunkChars = 30000
)

type Config struct {
	Provider           string
	Model              string
	APIKey             string
	Mode               Mode
	CloudRedactionMode CloudRedactionMode
	ReportDir          string
	TargetHints        []string
	Progress           io.Writer
	HTTPClient         *http.Client
	Client             Client
	Timeout            time.Duration
	Retries            int
	ChunkChars         int
	Resume             bool
	Now                func() time.Time
}

type CorpusFile struct {
	ID      string `json:"id"`
	Path    string `json:"path"`
	Kind    string `json:"kind"`
	BlobID  string `json:"blob_id,omitempty"`
	Size    int    `json:"size"`
	Content []byte `json:"-"`
}

type ManifestFile struct {
	ID          string `json:"id"`
	Kind        string `json:"kind"`
	Path        string `json:"path"`
	CloudPath   string `json:"cloud_path"`
	BlobID      string `json:"blob_id,omitempty"`
	Size        int    `json:"size"`
	LineCount   int    `json:"line_count"`
	ChunkCount  int    `json:"chunk_count"`
	SentToCloud bool   `json:"sent_to_cloud"`
	Skipped     bool   `json:"skipped"`
	SkipReason  string `json:"skip_reason,omitempty"`
}

type Manifest struct {
	GeneratedAt        time.Time          `json:"generated_at"`
	Provider           string             `json:"provider"`
	Model              string             `json:"model"`
	Mode               Mode               `json:"mode"`
	CloudRedactionMode CloudRedactionMode `json:"cloud_redaction_mode"`
	Files              []ManifestFile     `json:"files"`
}

type ProgressEvent struct {
	Time    time.Time      `json:"time"`
	Stage   string         `json:"stage"`
	Message string         `json:"message"`
	FileID  string         `json:"file_id,omitempty"`
	Index   int            `json:"index,omitempty"`
	Total   int            `json:"total,omitempty"`
	Extra   map[string]any `json:"extra,omitempty"`
}

type Client interface {
	Complete(ctx context.Context, req CompletionRequest) (CompletionResponse, error)
}

type CompletionRequest struct {
	SystemPrompt string
	UserPrompt   string
}

type CompletionResponse struct {
	Text string
}

type Result struct {
	ReportPath       string
	ManifestPath     string
	ProgressPath     string
	RedactionMapPath string
	FileCount        int
	ChunkCount       int
	CompletedChunks  int
	FailedChunks     int
	Partial          bool
	Provider         string
	Model            string
}
