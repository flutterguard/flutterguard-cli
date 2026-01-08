package analyzer

// Config contains configuration for the CLI analyzer
type Config struct {
	// Validation
	DisableNetworkChecks bool
	// Logging
	Verbose bool
}

// NewDefaultConfig returns a config with sensible defaults
func NewDefaultConfig() *Config {
	return &Config{
		DisableNetworkChecks: false,
	}
}
