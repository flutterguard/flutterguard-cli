package analyzer

import (
	"context"
	models "github.com/flutterguard/flutterguard-cli/models"
)

// DecompilerStrategy defines the interface for different decompiler implementations
type DecompilerStrategy interface {
	// Name returns the name of this decompiler strategy
	Name() string

	// Decompile extracts/decompiles an APK to the output directory
	Decompile(ctx context.Context, apkPath, outputDir string) error

	// CanHandle checks if this decompiler can handle the given APK
	CanHandle(apkPath string) (bool, error)

	// Priority returns the priority of this decompiler (higher = try first)
	Priority() int
}

// DecompilerResult contains the result of a decompilation attempt
type DecompilerResult struct {
	Strategy  string
	Success   bool
	Error     error
	OutputDir string
	Attempts  []models.DecompilationAttempt
}
