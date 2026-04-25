package ai

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type openAICompatibleClient struct {
	baseURL    string
	apiKey     string
	model      string
	provider   ProviderType
	httpClient *http.Client
}

type chatCompletionsRequest struct {
	Model       string        `json:"model"`
	Messages    []chatMessage `json:"messages"`
	Temperature float64       `json:"temperature,omitempty"`
	MaxTokens   int           `json:"max_tokens,omitempty"`
}

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatCompletionsResponse struct {
	Choices []struct {
		Message chatMessage `json:"message"`
	} `json:"choices"`
	Error *struct {
		Message string `json:"message"`
		Type    string `json:"type"`
		Code    string `json:"code"`
	} `json:"error,omitempty"`
}

func newOpenAICompatibleClient(cfg *AIConfig) AIClient {
	return &openAICompatibleClient{
		baseURL:  strings.TrimRight(cfg.BaseURL, "/"),
		apiKey:   cfg.APIKey,
		model:    cfg.Model,
		provider: cfg.Provider,
		httpClient: &http.Client{
			Timeout: 90 * time.Second,
		},
	}
}

func (c *openAICompatibleClient) ExplainFinding(finding string, context string) (string, error) {
	reqBody := chatCompletionsRequest{
		Model: c.model,
		Messages: []chatMessage{
			{Role: "system", Content: SystemPrompt()},
			{Role: "user", Content: fmt.Sprintf("Finding: %s\n\nContext:\n%s", finding, context)},
		},
		Temperature: 0.2,
		MaxTokens:   900,
	}

	payload, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("failed to marshal AI request: %w", err)
	}

	url := c.baseURL + "/chat/completions"
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return "", fmt.Errorf("failed to create AI request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Content-Type", "application/json")

	if c.provider == ProviderOpenRouter {
		req.Header.Set("HTTP-Referer", "https://github.com/flutterguard/flutterguard-cli")
		req.Header.Set("X-Title", "FlutterGuard CLI")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("AI request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4*1024*1024))
	if err != nil {
		return "", fmt.Errorf("failed to read AI response: %w", err)
	}

	var parsed chatCompletionsResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		if resp.StatusCode >= 400 {
			return "", fmt.Errorf("AI provider returned HTTP %d: %s", resp.StatusCode, truncateBody(string(body), 600))
		}
		return "", fmt.Errorf("failed to parse AI response: %w", err)
	}

	if resp.StatusCode >= 400 {
		if parsed.Error != nil && parsed.Error.Message != "" {
			return "", fmt.Errorf("AI provider error (HTTP %d): %s", resp.StatusCode, parsed.Error.Message)
		}
		return "", fmt.Errorf("AI provider returned HTTP %d", resp.StatusCode)
	}

	if parsed.Error != nil && parsed.Error.Message != "" {
		return "", fmt.Errorf("AI provider error: %s", parsed.Error.Message)
	}

	if len(parsed.Choices) == 0 || strings.TrimSpace(parsed.Choices[0].Message.Content) == "" {
		return "", fmt.Errorf("AI provider returned an empty completion")
	}

	return strings.TrimSpace(parsed.Choices[0].Message.Content), nil
}

func truncateBody(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
