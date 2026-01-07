package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

const Version = "1.0.0"

// CLIConfig holds CLI options passed via flags
type CLIConfig struct {
	OutputFormat           string
	OutputDir              string
	Verbose                bool
	EnableNetworkAndDNS    bool
}

var (
	apkPath     string
	cfg         CLIConfig
	showVersion bool
)

var rootCmd = &cobra.Command{
	Use:   "flutterguard",
	Short: "Local APK security analysis tool",
	Long:  "FlutterGuard CLI analyzes Android APKs (especially Flutter apps) for security insights and metadata.",
	RunE: func(cmd *cobra.Command, args []string) error {
		if showVersion {
			fmt.Printf("FlutterGuard CLI v%s\n", Version)
			fmt.Println("A local APK security analysis tool")
			return nil
		}

		if apkPath == "" {
			_ = cmd.Usage()
			return fmt.Errorf("--apk is required")
		}

		if cfg.OutputFormat != "json" && cfg.OutputFormat != "text" {
			return fmt.Errorf("unsupported output format: %s (allowed: json, text)", cfg.OutputFormat)
		}

		if _, err := os.Stat(apkPath); os.IsNotExist(err) {
			return fmt.Errorf("APK file not found: %s", apkPath)
		}

		absPath, err := filepath.Abs(apkPath)
		if err != nil {
			return fmt.Errorf("failed to get absolute path: %w", err)
		}

		if cfg.Verbose {
			fmt.Printf("FlutterGuard CLI v%s\n", Version)
			fmt.Printf("Analyzing: %s\n", absPath)
			fmt.Println("Starting analysis...")
		}

		// Network checks disabled by default unless --enable-network-and-dns-checks is set

		if err := runAnalysis(absPath, &cfg); err != nil {
			return fmt.Errorf("analysis failed: %w", err)
		}

		if cfg.Verbose {
			fmt.Println("\nAnalysis completed successfully!")
		}
		return nil
	},
	SilenceUsage:  true,
	SilenceErrors: true,
	Version:       Version,
}

// Execute runs the root Cobra command
func Execute() {
	// Flags
	rootCmd.Flags().StringVar(&apkPath, "apk", "", "Path to APK file to analyze (required)")
	rootCmd.Flags().StringVar(&cfg.OutputFormat, "format", "json", "Output format: json or text (used when --outDir not set)")
	rootCmd.Flags().StringVar(&cfg.OutputDir, "outDir", "", "Output directory for structured results (creates folder with app name)")
	rootCmd.Flags().BoolVar(&cfg.Verbose, "verbose", false, "Enable verbose output")
	rootCmd.Flags().BoolVar(&cfg.EnableNetworkAndDNS, "enable-network-and-dns-checks", false, "Enable DNS validation and network enrichment (default: offline)")
	rootCmd.Flags().BoolVar(&showVersion, "version", false, "Show version information")

	// Mark required flags
	_ = rootCmd.MarkFlagRequired("apk")

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
