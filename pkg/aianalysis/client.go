package aianalysis

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

func NewClient(cfg Config) (Client, error) {
	if cfg.Client != nil {
		return cfg.Client, nil
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 2 * time.Minute}
	}
	switch strings.ToLower(strings.TrimSpace(cfg.Provider)) {
	case "openai":
		return &openAIClient{apiKey: cfg.APIKey, model: cfg.Model, httpClient: client}, nil
	case "anthropic":
		return &anthropicClient{apiKey: cfg.APIKey, model: cfg.Model, httpClient: client}, nil
	default:
		return nil, fmt.Errorf("unsupported AI provider %q", cfg.Provider)
	}
}

type openAIClient struct {
	apiKey     string
	model      string
	httpClient *http.Client
}

func (c *openAIClient) Complete(ctx context.Context, req CompletionRequest) (CompletionResponse, error) {
	body := map[string]any{
		"model": c.model,
		"store": false,
		"input": []map[string]string{
			{"role": "system", "content": req.SystemPrompt},
			{"role": "user", "content": req.UserPrompt},
		},
	}
	data, err := json.Marshal(body)
	if err != nil {
		return CompletionResponse{}, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.openai.com/v1/responses", bytes.NewReader(data))
	if err != nil {
		return CompletionResponse{}, err
	}
	httpReq.Header.Set("Authorization", "Bearer "+c.apiKey)
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return CompletionResponse{}, err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 16*1024*1024))
	if err != nil {
		return CompletionResponse{}, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return CompletionResponse{}, fmt.Errorf("openai response HTTP %d: %s", resp.StatusCode, trimForError(respBody))
	}

	var parsed struct {
		OutputText string `json:"output_text"`
		Output     []struct {
			Content []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"content"`
		} `json:"output"`
	}
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return CompletionResponse{}, err
	}
	text := strings.TrimSpace(parsed.OutputText)
	if text == "" {
		var parts []string
		for _, item := range parsed.Output {
			for _, content := range item.Content {
				if content.Text != "" {
					parts = append(parts, content.Text)
				}
			}
		}
		text = strings.TrimSpace(strings.Join(parts, "\n\n"))
	}
	if text == "" {
		return CompletionResponse{}, fmt.Errorf("openai response did not include text output")
	}
	return CompletionResponse{Text: text}, nil
}

type anthropicClient struct {
	apiKey     string
	model      string
	httpClient *http.Client
}

func (c *anthropicClient) Complete(ctx context.Context, req CompletionRequest) (CompletionResponse, error) {
	body := map[string]any{
		"model":      c.model,
		"max_tokens": 4096,
		"system":     req.SystemPrompt,
		"messages": []map[string]string{
			{"role": "user", "content": req.UserPrompt},
		},
	}
	data, err := json.Marshal(body)
	if err != nil {
		return CompletionResponse{}, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.anthropic.com/v1/messages", bytes.NewReader(data))
	if err != nil {
		return CompletionResponse{}, err
	}
	httpReq.Header.Set("x-api-key", c.apiKey)
	httpReq.Header.Set("anthropic-version", "2023-06-01")
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return CompletionResponse{}, err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 16*1024*1024))
	if err != nil {
		return CompletionResponse{}, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return CompletionResponse{}, fmt.Errorf("anthropic response HTTP %d: %s", resp.StatusCode, trimForError(respBody))
	}

	var parsed struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return CompletionResponse{}, err
	}
	var parts []string
	for _, item := range parsed.Content {
		if item.Text != "" {
			parts = append(parts, item.Text)
		}
	}
	text := strings.TrimSpace(strings.Join(parts, "\n\n"))
	if text == "" {
		return CompletionResponse{}, fmt.Errorf("anthropic response did not include text output")
	}
	return CompletionResponse{Text: text}, nil
}

func trimForError(data []byte) string {
	text := strings.TrimSpace(string(data))
	if len(text) > 1000 {
		return text[:1000] + "..."
	}
	return text
}
