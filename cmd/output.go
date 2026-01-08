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
	// If outDir is not specified, default to current directory
	// and create the package-named folder there.
	if config.OutputDir == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("failed to get current directory: %w", err)
		}
		config.OutputDir = cwd
	}

	return saveStructuredOutput(results, config)
}

func saveStructuredOutput(results *models.Results, config *CLIConfig) error {

	appName := "app"
	if results.AAPT2Metadata != nil && results.AAPT2Metadata.Badging != nil && results.AAPT2Metadata.Badging.PackageName != "" {
		appName = sanitizeFileName(results.AAPT2Metadata.Badging.PackageName)
	} else if results.AppInfo.PackageName != "" {
		appName = sanitizeFileName(results.AppInfo.PackageName)
	} else if results.AppPackageName != "" {
		appName = sanitizeFileName(results.AppPackageName)
	}

	outDir := filepath.Join(config.OutputDir, appName)
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	if config.Verbose {
		fmt.Printf("Creating structured output in: %s\n", outDir)
	}

	if len(results.Emails) > 0 {
		if err := writeLines(filepath.Join(outDir, "emails.txt"), results.Emails); err != nil {
			return err
		}
	}

	if len(results.Domains) > 0 {
		if err := writeLines(filepath.Join(outDir, "domains.txt"), results.Domains); err != nil {
			return err
		}
	}

	allURLs := collectAllURLs(results)
	if len(allURLs) > 0 {
		if err := writeLines(filepath.Join(outDir, "urls.txt"), allURLs); err != nil {
			return err
		}
	}

	if len(results.APIEndpoints) > 0 {
		endpoints := make([]string, len(results.APIEndpoints))
		for i, ep := range results.APIEndpoints {
			endpoints[i] = fmt.Sprintf("[%s] %s", ep.Method, ep.URL)
		}
		if err := writeLines(filepath.Join(outDir, "api_endpoints.txt"), endpoints); err != nil {
			return err
		}
	}

	if len(results.Packages) > 0 {
		packages := make([]string, len(results.Packages))
		for i, pkg := range results.Packages {
			packages[i] = fmt.Sprintf("%s %s - https://pub.dev/packages/%s", pkg.Name, pkg.Version, pkg.Name)
		}
		if err := writeLines(filepath.Join(outDir, "packages.txt"), packages); err != nil {
			return err
		}
	}

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

	if len(results.HardcodedKeys) > 0 {
		if err := writeLines(filepath.Join(outDir, "hardcoded_keys.txt"), results.HardcodedKeys); err != nil {
			return err
		}
	}

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

	allAssets := append([]models.FileInfo{}, results.EnvFiles...)
	allAssets = append(allAssets, results.ConfigFiles...)
	allAssets = append(allAssets, results.ContentFiles...)
	allAssets = append(allAssets, results.VisualAssets...)

	if len(allAssets) > 0 {
		assetsDir := filepath.Join(outDir, "assets")
		if err := os.MkdirAll(assetsDir, 0755); err != nil {
			return fmt.Errorf("failed to create assets directory: %w", err)
		}

		filesByExt := make(map[string][]models.FileInfo)
		for _, file := range allAssets {
			ext := filepath.Ext(file.Name)
			if ext == "" {
				ext = "no_extension"
			} else {

				ext = strings.TrimPrefix(ext, ".")
			}
			filesByExt[ext] = append(filesByExt[ext], file)
		}

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

	hasDecompiled := false
	if results.DecompiledDirPath != "" {
		decompiledSrc := results.DecompiledDirPath
		decompiledDest := filepath.Join(outDir, "decompiled")

		if _, err := os.Stat(decompiledSrc); err == nil {
			hasDecompiled = true
			if err := copyDirectory(decompiledSrc, decompiledDest); err != nil {
				hasDecompiled = false
				if config.Verbose {
					fmt.Printf("Warning: failed to copy decompiled directory: %v\n", err)
				}
			}
		}
	}

	summaryMD := formatMarkdownSummary(results, allAssets)
	if err := os.WriteFile(filepath.Join(outDir, "summary.md"), []byte(summaryMD), 0644); err != nil {
		return fmt.Errorf("failed to write summary: %w", err)
	}

	analysisJSON, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal analysis: %w", err)
	}
	if err := os.WriteFile(filepath.Join(outDir, "analysis.json"), analysisJSON, 0644); err != nil {
		return fmt.Errorf("failed to write analysis: %w", err)
	}

	displayOutputSummary(results, outDir, allURLs, len(allAssets), hasDecompiled, config.Verbose)

	return nil
}

func displayOutputSummary(results *models.Results, outDir string, allURLs []string, assetCount int, hasDecompiled bool, verbose bool) {
	// App identity
	pkg := ""
	verName := ""
	verCode := ""
	minSDK := ""
	targetSDK := ""
	if results.AAPT2Metadata != nil && results.AAPT2Metadata.Badging != nil {
		b := results.AAPT2Metadata.Badging
		if b.PackageName != "" {
			pkg = b.PackageName
		}
		verName = b.VersionName
		verCode = b.VersionCode
		minSDK = b.MinSdkVersion
		targetSDK = b.TargetSdkVersion
	}
	if pkg == "" && results.AppInfo.PackageName != "" {
		pkg = results.AppInfo.PackageName
	}
	if verName == "" && results.AppInfo.VersionName != "" {
		verName = results.AppInfo.VersionName
	}
	if verCode == "" && results.AppInfo.VersionCode != "" {
		verCode = results.AppInfo.VersionCode
	}
	if minSDK == "" && results.AppInfo.MinSDKVersion != "" {
		minSDK = results.AppInfo.MinSDKVersion
	}
	if targetSDK == "" && results.AppInfo.TargetSDK != "" {
		targetSDK = results.AppInfo.TargetSDK
	}

	fmt.Fprintf(os.Stderr, "\n📊 Analysis Results\n")
	fmt.Fprintf(os.Stderr, "   Saved to: %s\n", outDir)
	if pkg != "" {
		if verName != "" || verCode != "" {
			fmt.Fprintf(os.Stderr, "   App: %s (v%s, code %s)\n", pkg, safeStr(verName), safeStr(verCode))
		} else {
			fmt.Fprintf(os.Stderr, "   App: %s\n", pkg)
		}
	}
	if minSDK != "" || targetSDK != "" {
		fmt.Fprintf(os.Stderr, "   SDK: min %s, target %s\n", safeStr(minSDK), safeStr(targetSDK))
	}
	fmt.Fprintln(os.Stderr)

	// High-level stats
	type kv struct {
		k string
		v int
	}
	stats := []kv{
		{"📧 Emails", len(results.Emails)},
		{"🌐 Domains", len(results.Domains)},
		{"🔗 URLs", len(allURLs)},
		{"🔌 API Endpoints", len(results.APIEndpoints)},
		{"📦 Packages", len(results.Packages)},
		{"🛡️ Permissions", len(results.Permissions)},
		{"🔑 Secrets", len(results.HardcodedKeys)},
		{"🔗 Services", len(results.Services)},
		{"🎨 Assets", assetCount},
	}
	if hasDecompiled {
		fmt.Fprintf(os.Stderr, "   📁 Decompiled: Full APK source\n")
	}
	// Print stats in two columns
	printed := 0
	for _, s := range stats {
		if s.v > 0 {
			fmt.Fprintf(os.Stderr, "   %s: %d", s.k, s.v)
			printed++
			if printed%2 == 0 {
				fmt.Fprintln(os.Stderr)
			} else {
				fmt.Fprint(os.Stderr, " |")
			}
		}
	}
	if printed%2 != 0 {
		fmt.Fprintln(os.Stderr)
	}

	// Highlights (top items)
	showTop := func(title string, items []string, limit int) {
		if len(items) == 0 {
			return
		}
		n := limit
		if len(items) < n {
			n = len(items)
		}
		fmt.Fprintf(os.Stderr, "\n%s:\n", title)
		for i := 0; i < n; i++ {
			fmt.Fprintf(os.Stderr, "   • %s\n", items[i])
		}
		if len(items) > n {
			fmt.Fprintf(os.Stderr, "   …and %d more\n", len(items)-n)
		}
	}

	if len(results.Domains) > 0 {
		showTop("Top domains", results.Domains, 5)
	}
	if len(results.APIEndpoints) > 0 {
		eps := make([]string, 0, len(results.APIEndpoints))
		for _, ep := range results.APIEndpoints {
			m := ep.Method
			if m == "" {
				m = "GET"
			}
			eps = append(eps, fmt.Sprintf("%s %s", m, ep.URL))
		}
		showTop("API endpoints", eps, 5)
	}
	if len(results.HardcodedKeys) > 0 {
		showTop("Potential secrets", results.HardcodedKeys, 5)
	}

	// Security quick glance
	securityLines := []string{}
	if results.CertificateInfo != nil {
		cc := len(results.CertificateInfo.Certificates)
		if cc > 0 {
			selfSigned := 0
			expired := 0
			for _, c := range results.CertificateInfo.Certificates {
				if c.IsSelfSigned {
					selfSigned++
				}
				if c.IsExpired {
					expired++
				}
			}
			securityLines = append(securityLines, fmt.Sprintf("Certificates: %d (self-signed: %d, expired: %d)", cc, selfSigned, expired))
		}
	}
	if results.NetworkSecurity != nil {
		if results.NetworkSecurity.CleartextAllowed {
			securityLines = append(securityLines, "Cleartext traffic: allowed")
		} else {
			securityLines = append(securityLines, "Cleartext traffic: disallowed")
		}
		if results.NetworkSecurity.CertificatePinning {
			securityLines = append(securityLines, "Certificate pinning: enabled")
		}
	}
	if results.Obfuscation != nil && results.Obfuscation.LikelyObfuscated {
		securityLines = append(securityLines, "Code obfuscation detected")
	}
	if len(securityLines) > 0 {
		fmt.Fprintf(os.Stderr, "\nSecurity:\n")
		for _, l := range securityLines {
			fmt.Fprintf(os.Stderr, "   • %s\n", l)
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

func safeStr(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
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

	if err := os.MkdirAll(dest, 0755); err != nil {
		return fmt.Errorf("failed to create destination directory: %w", err)
	}

	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		relPath, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}

		destPath := filepath.Join(dest, relPath)

		if info.IsDir() {

			return os.MkdirAll(destPath, 0755)
		}

		return copyFileTo(path, destPath)
	})
}
