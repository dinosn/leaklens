package aianalysis

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func NewClient(cfg Config) (Client, error) {
	if cfg.Client != nil {
		return cfg.Client, nil
	}
	client := cfg.HTTPClient
	if client == nil {
		timeout := cfg.Timeout
		if timeout <= 0 {
			timeout = DefaultAITimeout
		}
		client = &http.Client{Timeout: timeout}
	}
	retries := cfg.Retries
	if retries < 0 {
		retries = DefaultAIRetries
	}
	switch strings.ToLower(strings.TrimSpace(cfg.Provider)) {
	case "openai":
		return &openAIClient{apiKey: cfg.APIKey, model: cfg.Model, httpClient: client, retries: retries}, nil
	case "anthropic":
		return &anthropicClient{apiKey: cfg.APIKey, model: cfg.Model, httpClient: client, retries: retries}, nil
	default:
		return nil, fmt.Errorf("unsupported AI provider %q", cfg.Provider)
	}
}

type openAIClient struct {
	apiKey     string
	model      string
	httpClient *http.Client
	retries    int
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
	respBody, err := c.doWithRetry(ctx, "https://api.openai.com/v1/responses", data)
	if err != nil {
		return CompletionResponse{}, err
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
	retries    int
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
	respBody, err := c.doWithRetry(ctx, "https://api.anthropic.com/v1/messages", data)
	if err != nil {
		return CompletionResponse{}, err
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

func (c *openAIClient) doWithRetry(ctx context.Context, endpoint string, data []byte) ([]byte, error) {
	return doAIRequestWithRetry(ctx, c.httpClient, c.retries, func() (*http.Request, error) {
		httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		httpReq.Header.Set("Authorization", "Bearer "+c.apiKey)
		httpReq.Header.Set("Content-Type", "application/json")
		return httpReq, nil
	})
}

func (c *anthropicClient) doWithRetry(ctx context.Context, endpoint string, data []byte) ([]byte, error) {
	return doAIRequestWithRetry(ctx, c.httpClient, c.retries, func() (*http.Request, error) {
		httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		httpReq.Header.Set("x-api-key", c.apiKey)
		httpReq.Header.Set("anthropic-version", "2023-06-01")
		httpReq.Header.Set("Content-Type", "application/json")
		return httpReq, nil
	})
}

type aiHTTPError struct {
	status     int
	body       string
	retryAfter time.Duration
}

func (e aiHTTPError) Error() string {
	return fmt.Sprintf("HTTP %d: %s", e.status, e.body)
}

func doAIRequestWithRetry(ctx context.Context, client *http.Client, retries int, newRequest func() (*http.Request, error)) ([]byte, error) {
	var lastErr error
	for attempt := 0; attempt <= retries; attempt++ {
		req, err := newRequest()
		if err != nil {
			return nil, err
		}
		body, err := doAIRequest(client, req)
		if err == nil {
			return body, nil
		}
		lastErr = err
		if ctx.Err() != nil || attempt == retries || !isRetryableAIError(err) {
			break
		}
		delay := retryDelay(attempt, err)
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
	return nil, lastErr
}

func doAIRequest(client *http.Client, req *http.Request) ([]byte, error) {
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 16*1024*1024))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, aiHTTPError{
			status:     resp.StatusCode,
			body:       trimForError(respBody),
			retryAfter: parseRetryAfter(resp.Header.Get("Retry-After")),
		}
	}
	return respBody, nil
}

func isRetryableAIError(err error) bool {
	var httpErr aiHTTPError
	if errors.As(err, &httpErr) {
		return httpErr.status == http.StatusRequestTimeout ||
			httpErr.status == http.StatusTooManyRequests ||
			httpErr.status >= 500
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	message := err.Error()
	return strings.Contains(message, "Client.Timeout exceeded") ||
		strings.Contains(message, "context deadline exceeded") ||
		strings.Contains(message, "connection reset by peer") ||
		strings.Contains(message, "temporary failure")
}

func retryDelay(attempt int, err error) time.Duration {
	var httpErr aiHTTPError
	if errors.As(err, &httpErr) && httpErr.retryAfter > 0 {
		return httpErr.retryAfter
	}
	delay := time.Duration(1<<attempt) * time.Second
	if delay > 15*time.Second {
		return 15 * time.Second
	}
	return delay
}

func parseRetryAfter(value string) time.Duration {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}
	if seconds, err := strconv.Atoi(value); err == nil && seconds > 0 {
		return time.Duration(seconds) * time.Second
	}
	if when, err := http.ParseTime(value); err == nil {
		delay := time.Until(when)
		if delay > 0 {
			return delay
		}
	}
	return 0
}

func trimForError(data []byte) string {
	text := strings.TrimSpace(string(data))
	if len(text) > 1000 {
		return text[:1000] + "..."
	}
	return text
}
