package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/flutterguard/flutterguard-cli/analyzer"
)

// Stage descriptions for user-friendly output
var stageDescriptions = map[string]string{
	"init":      "🔍 Initializing analysis",
	"aapt2":     "📦 Extracting APK metadata",
	"decompile": "📂 Decompiling APK",
	"extract":   "🔎 Extracting files and data",
	"packages":  "📚 Analyzing packages",
	"manifest":  "📄 Parsing manifest",
	"services":  "🔗 Detecting services",
	"assets":    "🎨 Processing assets",
	"done":      "✅ Analysis complete",
}

func runAnalysis(apkPath string, config *CLIConfig) error {
	// Create analyzer with CLI config
	cliCfg := &analyzer.Config{
		DisableNetworkChecks: !config.EnableNetworkAndDNS,
	}

	a := analyzer.NewAnalyzer(cliCfg)

	// Progress reporter with different behavior based on verbose flag
	var progressReporter analyzer.ProgressReporter
	lastStage := ""
	lastPercent := 0

	progressReporter = func(evt analyzer.ProgressEvent) {
		if config.Verbose {
			// Detailed verbose output with progress bar
			displayVerboseProgress(evt)
		} else {
			// Simple, clean progress output (only on stage change or significant progress)
			displaySimpleProgress(evt, &lastStage, &lastPercent)
		}
	}

	// Show starting message
	if !config.Verbose {
		fmt.Fprintf(os.Stderr, "🚀 Analyzing: %s\n", filepath.Base(apkPath))
	} else {
		fmt.Fprintf(os.Stderr, "🚀 Starting analysis...\n")
	}

	// Run analysis with timeout context
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Minute)
	defer cancel()

	startTime := time.Now()
	results, err := a.AnalyzeAPK(ctx, apkPath, progressReporter)
	if err != nil {
		return fmt.Errorf("\n❌ Analysis failed: %w", err)
	}
	duration := time.Since(startTime)

	if config.Verbose {
		fmt.Fprintf(os.Stderr, "\n⏱️  Analysis completed in %s\n", formatDuration(duration))
	} else {
		fmt.Fprintf(os.Stderr, "✅ Done in %s\n\n", formatDuration(duration))
	}

	// Format and output results
	return outputResults(results, config)
}

func displayVerboseProgress(evt analyzer.ProgressEvent) {
	// Get user-friendly stage description
	stageDesc, ok := stageDescriptions[evt.Stage]
	if !ok {
		stageDesc = fmt.Sprintf("📍 %s", evt.Stage)
	}

	// Include detail if available
	if evt.Detail != "" {
		stageDesc = fmt.Sprintf("%s: %s", stageDesc, evt.Detail)
	}

	// Display with progress bar
	barLength := 30
	filledLength := int(float64(barLength) * float64(evt.Percent) / 100.0)
	bar := strings.Repeat("█", filledLength) + strings.Repeat("░", barLength-filledLength)

	fmt.Fprintf(os.Stderr, "\r[%s] %3d%% %s", bar, evt.Percent, stageDesc)

	if evt.Percent >= 100 {
		fmt.Fprintf(os.Stderr, "\n")
	}
}

func displaySimpleProgress(evt analyzer.ProgressEvent, lastStage *string, lastPercent *int) {
	// Only show when stage changes (not on every progress event)
	if evt.Stage != *lastStage {
		*lastStage = evt.Stage
		stageDesc, ok := stageDescriptions[evt.Stage]
		if !ok {
			stageDesc = fmt.Sprintf("📍 %s", evt.Stage)
		}
		fmt.Fprintf(os.Stderr, "%s\n", stageDesc)
	}

	// Update last percent
	*lastPercent = evt.Percent
}

func formatDuration(d time.Duration) string {
	d = d.Round(time.Second)
	minutes := int(d.Minutes())
	seconds := int(d.Seconds()) % 60

	if minutes > 0 {
		return fmt.Sprintf("%dm %ds", minutes, seconds)
	}
	return fmt.Sprintf("%ds", seconds)
}

