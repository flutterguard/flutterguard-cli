package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	models "github.com/flutterguard/flutterguard-cli/models"
)

func outputResults(results *models.Results, config *CLIConfig) error {
	// If --outDir is set, create structured output directory
	if config.OutputDir != "" {
		return saveStructuredOutput(results, config)
	}

	// Otherwise, output to stdout in requested format
	var output []byte
	var err error

	switch config.OutputFormat {
	case "json":
		output, err = json.MarshalIndent(results, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal results: %w", err)
		}
	case "text":
		output = []byte(formatTextReport(results))
	default:
		return fmt.Errorf("unsupported output format: %s", config.OutputFormat)
	}

	fmt.Println(string(output))
	return nil
}

func saveStructuredOutput(results *models.Results, config *CLIConfig) error {
	// Determine app name from package or APK info
	appName := "app"
	if results.AAPT2Metadata != nil && results.AAPT2Metadata.Badging != nil && results.AAPT2Metadata.Badging.PackageName != "" {
		appName = sanitizeFileName(results.AAPT2Metadata.Badging.PackageName)
	} else if results.AppInfo.PackageName != "" {
		appName = sanitizeFileName(results.AppInfo.PackageName)
	} else if results.AppPackageName != "" {
		appName = sanitizeFileName(results.AppPackageName)
	}

	// Create output directory with app name
	outDir := filepath.Join(config.OutputDir, appName)
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	if config.Verbose {
		fmt.Printf("Creating structured output in: %s\n", outDir)
	}

	// Save emails.txt
	if len(results.Emails) > 0 {
		if err := writeLines(filepath.Join(outDir, "emails.txt"), results.Emails); err != nil {
			return err
		}
	}

	// Save domains.txt
	if len(results.Domains) > 0 {
		if err := writeLines(filepath.Join(outDir, "domains.txt"), results.Domains); err != nil {
			return err
		}
	}

	// Save urls.txt (all URL types combined)
	allURLs := collectAllURLs(results)
	if len(allURLs) > 0 {
		if err := writeLines(filepath.Join(outDir, "urls.txt"), allURLs); err != nil {
			return err
		}
	}

	// Save api_endpoints.txt
	if len(results.APIEndpoints) > 0 {
		endpoints := make([]string, len(results.APIEndpoints))
		for i, ep := range results.APIEndpoints {
			endpoints[i] = fmt.Sprintf("[%s] %s", ep.Method, ep.URL)
		}
		if err := writeLines(filepath.Join(outDir, "api_endpoints.txt"), endpoints); err != nil {
			return err
		}
	}

	// Save packages.txt
	if len(results.Packages) > 0 {
		packages := make([]string, len(results.Packages))
		for i, pkg := range results.Packages {
			packages[i] = fmt.Sprintf("%s %s - https://pub.dev/packages/%s", pkg.Name, pkg.Version, pkg.Name)
		}
		if err := writeLines(filepath.Join(outDir, "packages.txt"), packages); err != nil {
			return err
		}
	}

	// Save permissions.txt
	if len(results.Permissions) > 0 {
		perms := make([]string, len(results.Permissions))
		for i, perm := range results.Permissions {
			dangerous := ""
			if perm.Dangerous {
				dangerous = " [DANGEROUS]"
			}
			perms[i] = fmt.Sprintf("%s%s", perm.Name, dangerous)
		}
		if err := writeLines(filepath.Join(outDir, "permissions.txt"), perms); err != nil {
			return err
		}
	}

	// Save hardcoded_keys.txt if found
	if len(results.HardcodedKeys) > 0 {
		if err := writeLines(filepath.Join(outDir, "hardcoded_keys.txt"), results.HardcodedKeys); err != nil {
			return err
		}
	}

	// Save services.txt
	if len(results.Services) > 0 {
		services := make([]string, 0)
		for _, svc := range results.Services {
			services = append(services, fmt.Sprintf("=== %s ===", svc.Name))
			if len(svc.Indicators) > 0 {
				services = append(services, "Indicators:")
				for _, ind := range svc.Indicators {
					services = append(services, fmt.Sprintf("  - %s", ind))
				}
			}
			if len(svc.Domains) > 0 {
				services = append(services, "Domains:")
				for _, d := range svc.Domains {
					services = append(services, fmt.Sprintf("  - %s", d))
				}
			}
			services = append(services, "")
		}
		if err := writeLines(filepath.Join(outDir, "services.txt"), services); err != nil {
			return err
		}
	}

	// Create assets/ directory and copy files grouped by extension
	allAssets := append([]models.FileInfo{}, results.EnvFiles...)
	allAssets = append(allAssets, results.ConfigFiles...)
	allAssets = append(allAssets, results.ContentFiles...)
	allAssets = append(allAssets, results.VisualAssets...)

	if len(allAssets) > 0 {
		assetsDir := filepath.Join(outDir, "assets")
		if err := os.MkdirAll(assetsDir, 0755); err != nil {
			return fmt.Errorf("failed to create assets directory: %w", err)
		}

		// Group files by extension
		filesByExt := make(map[string][]models.FileInfo)
		for _, file := range allAssets {
			ext := filepath.Ext(file.Name)
			if ext == "" {
				ext = "no_extension"
			} else {
				// Remove leading dot
				ext = strings.TrimPrefix(ext, ".")
			}
			filesByExt[ext] = append(filesByExt[ext], file)
		}

		// Create a folder for each extension and copy files
		for ext, files := range filesByExt {
			extDir := filepath.Join(assetsDir, ext)
			if err := os.MkdirAll(extDir, 0755); err != nil {
				return fmt.Errorf("failed to create extension directory %s: %w", ext, err)
			}

			for _, file := range files {
				if err := copyFileToDir(file.Path, extDir); err != nil && config.Verbose {
					fmt.Printf("Warning: failed to copy %s: %v\n", file.Name, err)
				}
			}
		}
	}

	// Copy decompiled directory if available
	if results.DecompiledDirPath != "" {
		decompiledSrc := results.DecompiledDirPath
		decompiledDest := filepath.Join(outDir, "decompiled")
		
		if _, err := os.Stat(decompiledSrc); err == nil {
			if err := copyDirectory(decompiledSrc, decompiledDest); err != nil {
				if config.Verbose {
					fmt.Printf("Warning: failed to copy decompiled directory: %v\n", err)
				}
			}
		}
	}

	// Save summary.md (human-readable markdown summary with navigation)
	summaryMD := formatMarkdownSummary(results, allAssets)
	if err := os.WriteFile(filepath.Join(outDir, "summary.md"), []byte(summaryMD), 0644); err != nil {
		return fmt.Errorf("failed to write summary: %w", err)
	}

	// Save full analysis.json
	analysisJSON, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal analysis: %w", err)
	}
	if err := os.WriteFile(filepath.Join(outDir, "analysis.json"), analysisJSON, 0644); err != nil {
		return fmt.Errorf("failed to write analysis: %w", err)
	}

	// Display summary to user
	displayOutputSummary(results, outDir, allURLs, len(allAssets), results.DecompiledDirPath != "", config.Verbose)

	return nil
}

func displayOutputSummary(results *models.Results, outDir string, allURLs []string, assetCount int, hasDecompiled bool, verbose bool) {
	fmt.Fprintf(os.Stderr, "\n📊 Analysis Results:\n")
	fmt.Fprintf(os.Stderr, "   Saved to: %s\n\n", outDir)

	// Create a summary stats display
	stats := make([]string, 0)

	if len(results.Emails) > 0 {
		stats = append(stats, fmt.Sprintf("   📧 Emails: %d", len(results.Emails)))
	}
	if len(results.Domains) > 0 {
		stats = append(stats, fmt.Sprintf("   🌐 Domains: %d", len(results.Domains)))
	}
	if len(allURLs) > 0 {
		stats = append(stats, fmt.Sprintf("   🔗 URLs: %d", len(allURLs)))
	}
	if len(results.APIEndpoints) > 0 {
		stats = append(stats, fmt.Sprintf("   🔌 API Endpoints: %d", len(results.APIEndpoints)))
	}
	if len(results.Packages) > 0 {
		stats = append(stats, fmt.Sprintf("   📦 Packages: %d", len(results.Packages)))
	}
	if len(results.Permissions) > 0 {
		stats = append(stats, fmt.Sprintf("   🛡️  Permissions: %d", len(results.Permissions)))
	}
	if len(results.HardcodedKeys) > 0 {
		stats = append(stats, fmt.Sprintf("   🔑 Secrets: %d", len(results.HardcodedKeys)))
	}
	if len(results.Services) > 0 {
		stats = append(stats, fmt.Sprintf("   🔗 Services: %d", len(results.Services)))
	}
	if assetCount > 0 {
		stats = append(stats, fmt.Sprintf("   🎨 Assets: %d files", assetCount))
	}
	if hasDecompiled {
		stats = append(stats, fmt.Sprintf("   📁 Decompiled: Full APK source"))
	}

	// Display stats in columns
	for i := 0; i < len(stats); i++ {
		fmt.Fprintf(os.Stderr, "%s", stats[i])
		if (i+1)%2 == 0 || i == len(stats)-1 {
			fmt.Fprintf(os.Stderr, "\n")
		} else {
			fmt.Fprintf(os.Stderr, " | ")
		}
	}

	if verbose {
		fmt.Fprintf(os.Stderr, "\n📝 Files created:\n")
		fmt.Fprintf(os.Stderr, "   ✓ summary.md (start here!)\n")
		fmt.Fprintf(os.Stderr, "   ✓ analysis.json (full data)\n")
		if len(results.Emails) > 0 {
			fmt.Fprintf(os.Stderr, "   ✓ emails.txt\n")
		}
		if len(results.Domains) > 0 {
			fmt.Fprintf(os.Stderr, "   ✓ domains.txt\n")
		}
		if len(allURLs) > 0 {
			fmt.Fprintf(os.Stderr, "   ✓ urls.txt\n")
		}
		if len(results.APIEndpoints) > 0 {
			fmt.Fprintf(os.Stderr, "   ✓ api_endpoints.txt\n")
		}
		if len(results.Packages) > 0 {
			fmt.Fprintf(os.Stderr, "   ✓ packages.txt\n")
		}
		if len(results.Permissions) > 0 {
			fmt.Fprintf(os.Stderr, "   ✓ permissions.txt\n")
		}
		if len(results.HardcodedKeys) > 0 {
			fmt.Fprintf(os.Stderr, "   ✓ hardcoded_keys.txt\n")
		}
		if len(results.Services) > 0 {
			fmt.Fprintf(os.Stderr, "   ✓ services.txt\n")
		}
		if assetCount > 0 {
			fmt.Fprintf(os.Stderr, "   ✓ assets/ (organized by file type)\n")
		}
		if hasDecompiled {
			fmt.Fprintf(os.Stderr, "   ✓ decompiled/ (full APK source)\n")
		}
	}

	fmt.Fprintf(os.Stderr, "\n💡 Tip: Open summary.md in your editor or GitHub to see everything organized!\n\n")
}

func sanitizeFileName(name string) string {
	// Replace invalid filename characters
	name = strings.ReplaceAll(name, "/", "_")
	name = strings.ReplaceAll(name, "\\", "_")
	name = strings.ReplaceAll(name, ":", "_")
	name = strings.ReplaceAll(name, "*", "_")
	name = strings.ReplaceAll(name, "?", "_")
	name = strings.ReplaceAll(name, "\"", "_")
	name = strings.ReplaceAll(name, "<", "_")
	name = strings.ReplaceAll(name, ">", "_")
	name = strings.ReplaceAll(name, "|", "_")
	return name
}

func writeLines(path string, lines []string) error {
	content := strings.Join(lines, "\n") + "\n"
	return os.WriteFile(path, []byte(content), 0644)
}

func collectAllURLs(results *models.Results) []string {
	var urls []string
	urls = append(urls, results.URLs.HTTP...)
	urls = append(urls, results.URLs.HTTPS...)
	urls = append(urls, results.URLs.FTP...)
	urls = append(urls, results.URLs.WS...)
	urls = append(urls, results.URLs.WSS...)
	urls = append(urls, results.URLs.File...)
	urls = append(urls, results.URLs.Content...)
	urls = append(urls, results.URLs.Other...)
	return urls
}

func copyFileToDir(srcPath, destDir string) error {
	fileName := filepath.Base(srcPath)
	destPath := filepath.Join(destDir, fileName)
	return copyFileTo(srcPath, destPath)
}

func copyFileTo(srcPath, destPath string) error {
	data, err := os.ReadFile(srcPath)
	if err != nil {
		return err
	}
	return os.WriteFile(destPath, data, 0644)
}

func copyDirectory(src, dest string) error {
	// Create destination directory
	if err := os.MkdirAll(dest, 0755); err != nil {
		return fmt.Errorf("failed to create destination directory: %w", err)
	}

	// Walk through source directory
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Calculate relative path
		relPath, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}

		destPath := filepath.Join(dest, relPath)

		if info.IsDir() {
			// Create directory in destination
			return os.MkdirAll(destPath, 0755)
		}

		// Copy file
		return copyFileTo(path, destPath)
	})
}
