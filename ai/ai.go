package ai

// ProviderType represents a supported AI provider.
type ProviderType string

const (
	ProviderOpenAI     ProviderType = "openai"
	ProviderGemini     ProviderType = "gemini"
	ProviderClaude     ProviderType = "claude"
	ProviderOpenRouter ProviderType = "openrouter"
	ProviderXAI        ProviderType = "xai"
)

// AIProviderConfig holds configuration for an AI provider.
type AIProviderConfig struct {
	Provider ProviderType
	APIKey   string
	BaseURL  string // Optional, for custom endpoints
}

// AIClient is the interface for all AI providers.
type AIClient interface {
	ExplainFinding(finding string, context string) (string, error)
}

// SystemPrompt returns the system prompt for remediation guidance.
func SystemPrompt() string {
	return `You are a professional Flutter and Android security expert. For each finding, provide a clear, actionable, and human-like remediation guide. Include code snippets, links to best practices, and explain the risk in simple terms. Be concise, accurate, and friendly. Assume the reader is a developer or security engineer.`
}
