package ai

import (
	"fmt"
)

// NewAIClient returns an AIClient for the given config.
func NewAIClient(cfg *AIConfig) AIClient {
	switch cfg.Provider {
	case ProviderOpenAI:
		// return &OpenAIClient{...} // To be implemented
	case ProviderGemini:
		// return &GeminiClient{...} // To be implemented
	case ProviderClaude:
		// return &ClaudeClient{...} // To be implemented
	case ProviderOpenRouter:
		// return &OpenRouterClient{...} // To be implemented
	case ProviderXAI:
		// return &XAIClient{...} // To be implemented
	}
	return &DummyAIClient{}
}

// ExplainWithAI runs AI remediation for a finding.
func ExplainWithAI(client AIClient, finding, context string) string {
	msg, err := client.ExplainFinding(finding, context)
	if err != nil {
		return fmt.Sprintf("[AI Error] %v", err)
	}
	return msg
}
