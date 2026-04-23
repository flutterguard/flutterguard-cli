package ai

import (
	"os"
)

// AIConfig holds global AI integration settings.
type AIConfig struct {
	Enabled  bool
	Provider ProviderType
	APIKey   string
	BaseURL  string
}

// LoadAIConfig loads AI config from environment variables or flags.
func LoadAIConfig() *AIConfig {
	return &AIConfig{
		Enabled:  os.Getenv("FLUTTERGUARD_AI_ENABLED") == "1",
		Provider: ProviderType(os.Getenv("FLUTTERGUARD_AI_PROVIDER")),
		APIKey:   os.Getenv("FLUTTERGUARD_AI_KEY"),
		BaseURL:  os.Getenv("FLUTTERGUARD_AI_BASEURL"),
	}
}
