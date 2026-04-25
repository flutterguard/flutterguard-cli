package ai

import (
	"fmt"
)

// NewAIClient returns an AIClient for the given config.
func NewAIClient(cfg *AIConfig) (AIClient, error) {
	if cfg == nil {
		return nil, fmt.Errorf("AI config is required")
	}
	if cfg.APIKey == "" {
		return nil, fmt.Errorf("AI API key is required")
	}

	switch cfg.Provider {
	case ProviderOpenAI:
		if cfg.BaseURL == "" {
			cfg.BaseURL = "https://api.openai.com/v1"
		}
		if cfg.Model == "" {
			cfg.Model = "gpt-4o-mini"
		}
		return newOpenAICompatibleClient(cfg), nil
	case ProviderGemini:
		return nil, fmt.Errorf("provider %q is not implemented yet", cfg.Provider)
	case ProviderClaude:
		return nil, fmt.Errorf("provider %q is not implemented yet", cfg.Provider)
	case ProviderOpenRouter:
		if cfg.BaseURL == "" {
			cfg.BaseURL = "https://openrouter.ai/api/v1"
		}
		if cfg.Model == "" {
			cfg.Model = "openai/gpt-4o-mini"
		}
		return newOpenAICompatibleClient(cfg), nil
	case ProviderXAI:
		if cfg.BaseURL == "" {
			cfg.BaseURL = "https://api.x.ai/v1"
		}
		if cfg.Model == "" {
			cfg.Model = "grok-2-latest"
		}
		return newOpenAICompatibleClient(cfg), nil
	default:
		return nil, fmt.Errorf("unsupported AI provider %q", cfg.Provider)
	}
}

// ExplainWithAI runs AI remediation for a finding.
func ExplainWithAI(client AIClient, finding, context string) string {
	msg, err := client.ExplainFinding(finding, context)
	if err != nil {
		return fmt.Sprintf("[AI Error] %v", err)
	}
	return msg
}
