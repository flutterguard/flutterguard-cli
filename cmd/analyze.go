package cmd

import (
	"context"
	"fmt"
	"time"

	"github.com/flutterguard/flutterguard-cli/analyzer"
)

func runAnalysis(apkPath string, config *CLIConfig) error {
	// Create analyzer with CLI config
	cliCfg := &analyzer.Config{
		DisableNetworkChecks: !config.EnableNetworkAndDNS,
	}

	a := analyzer.NewAnalyzer(cliCfg)

	// Progress reporter for verbose mode with stage labels
	var progressReporter analyzer.ProgressReporter
	if config.Verbose {
		progressReporter = func(evt analyzer.ProgressEvent) {
			stage := evt.Stage
			if evt.Detail != "" {
				stage = fmt.Sprintf("%s: %s", stage, evt.Detail)
			}
			fmt.Printf("\r[%3d%%] %s", evt.Percent, stage)
			if evt.Percent >= 100 {
				fmt.Print("\n")
			}
		}
	}

	// Run analysis with timeout context
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Minute)
	defer cancel()

	startTime := time.Now()
	results, err := a.AnalyzeAPK(ctx, apkPath, progressReporter)
	if err != nil {
		return fmt.Errorf("analysis failed: %w", err)
	}
	duration := time.Since(startTime)

	if config.Verbose {
		fmt.Printf("\nAnalysis took: %v\n", duration)
	}

	// Format and output results
	return outputResults(results, config)
}
