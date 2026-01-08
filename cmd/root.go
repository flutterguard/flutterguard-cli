package cmd

	rootCmd.SetHelpTemplate(`FlutterGuard CLI - Analyze Flutter Android APKs for security insights

Usage:
	{{.UseLine}}

{{if .HasAvailableFlags}}Options:
{{.LocalFlags.FlagUsages | trimTrailingWhitespaces}}
{{end}}
{{if .HasAvailableSubCommands}}Commands:
{{range .Commands}}{{if (or .IsAvailableCommand (eq .Name "help"))}}
	{{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}
{{end}}
Examples:
	# Analyze APK with structured output (recommended)
	{{.CommandPath}} --apk app.apk --outDir ./results --verbose

	# Quick text report
	{{.CommandPath}} --apk app.apk --format text

	# Offline analysis (default)
	{{.CommandPath}} --apk app.apk --outDir ./results

	# Enable network checks for full validation
	{{.CommandPath}} --apk app.apk --outDir ./results --enable-network-and-dns-checks

More info: https://github.com/flutterguard/flutterguard-cli
`)
		}
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		if showVersion {
			fmt.Printf("FlutterGuard CLI v%s\n", Version)
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

func init() {

	rootCmd.SetHelpTemplate(`   ___ _       _   _             ___                     _ 
  / __\ |_   _| |_| |_ ___ _ __ / _ \/\ /\  __ _ _ __ __| |
 / _\ | | | | | __| __/ _ \ '__/ /_\/ / \ \/ _` + "`" + ` | '__/ _` + "`" + ` |
/ /   | | |_| | |_| ||  __/ | / /_\\\ \_/ / (_| | | | (_| |
\/    |_|\__,_|\__|\__\___|_| \____/ \___/ \__,_|_|  \__,_|
                                                           

USAGE:
  {{.UseLine}}



{{end}}{{if .HasAvailableFlags}}OPTIONS:
{{.LocalFlags.FlagUsages | trimTrailingWhitespaces}}

{{end}}{{if .HasAvailableSubCommands}}COMMANDS:
{{range .Commands}}{{if (or .IsAvailableCommand (eq .Name "help"))}}
  {{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}
{{end}}EXAMPLES:
  # Analyze APK with structured output (recommended)
  {{.CommandPath}} --apk app.apk --outDir ./results --verbose

  # Quick text report
  {{.CommandPath}} --apk app.apk --format text

  # Offline analysis (default)
  {{.CommandPath}} --apk app.apk --outDir ./results

  # Enable network checks for full validation
  {{.CommandPath}} --apk app.apk --outDir ./results --enable-network-and-dns-checks

For more information, visit: https://github.com/flutterguard/flutterguard-cli
`)
}

// Execute runs the root Cobra command
func Execute() {

	rootCmd.Flags().StringVar(&apkPath, "apk", "", "Flutter app APK file to analyze")
	rootCmd.Flags().StringVar(&cfg.OutputFormat, "format", "json", "Output format: json or text (used when --outDir not set)")
	rootCmd.Flags().StringVar(&cfg.OutputDir, "outDir", "", "Output directory for structured results (creates folder with app package name), if not set, outputs to stdout")
	rootCmd.Flags().BoolVar(&cfg.Verbose, "verbose", false, "Enable verbose output")
	rootCmd.Flags().BoolVar(&cfg.EnableNetworkAndDNS, "enable-network-and-dns-checks", false, "Enable DNS validation and network enrichment for all domains, endpoints, packages... (default: offline)")
	rootCmd.Flags().BoolVar(&showVersion, "version", false, "Show version information")

	_ = rootCmd.MarkFlagRequired("apk")

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
