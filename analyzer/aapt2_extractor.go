package analyzer

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"os/exec"
	"regexp"
	"strings"

	models "github.com/flutterguard/flutterguard-cli/models"
)

// AAPT2Extractor handles extraction of metadata using aapt2 command
type AAPT2Extractor struct {
	cfg *Config
}

func NewAAPT2Extractor(cfg *Config) *AAPT2Extractor {
	return &AAPT2Extractor{cfg: cfg}
}

// IsAvailable checks if aapt2 command is available in PATH
func (a *AAPT2Extractor) IsAvailable() bool {
	path, err := exec.LookPath("aapt2")
	if err != nil {
		if a.cfg.Verbose {
			log.Printf("[AAPT2] aapt2 not found in PATH: %v", err)
		}
		return false
	}
	if a.cfg.Verbose {
		log.Printf("[AAPT2] Found aapt2 at: %s", path)
	} else {
	}
	return true
}

// ExtractMetadata extracts all aapt2 metadata from an APK file
func (a *AAPT2Extractor) ExtractMetadata(ctx context.Context, apkPath string) (*models.AAPT2Metadata, error) {
	if !a.IsAvailable() {
		return nil, fmt.Errorf("aapt2 command not available in PATH")
	}

	metadata := &models.AAPT2Metadata{}

	badgingData, err := a.ExtractBadging(ctx, apkPath)
	if err == nil {
		metadata.Badging = badgingData
	}

	packageName, err := a.ExtractPackageName(ctx, apkPath)
	if err == nil {
		metadata.PackageName = packageName
	}

	permissions, err := a.ExtractPermissions(ctx, apkPath)
	if err == nil {
		metadata.Permissions = permissions
	}

	strings, err := a.ExtractStrings(ctx, apkPath)
	if err == nil {
		metadata.ExtractedStrings = strings
	}

	return metadata, nil
}

// ExtractBadging extracts badging information using aapt2 dump badging
func (a *AAPT2Extractor) ExtractBadging(ctx context.Context, apkPath string) (*models.AAPT2BadgingInfo, error) {
	cmd := exec.CommandContext(ctx, "aapt2", "dump", "badging", apkPath)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if a.cfg.Verbose {
		log.Printf("[AAPT2] Executing: %s %s %s %s %s", "aapt2", "dump", "badging", apkPath, "")
	}

	if err := cmd.Run(); err != nil {
		if a.cfg.Verbose {
			log.Printf("[AAPT2] Command failed: %v (stderr: %s)", err, stderr.String())
		}
		return nil, fmt.Errorf("aapt2 dump badging failed: %w (stderr: %s)", err, stderr.String())
	}

	output := stdout.String()
	badging := a.parseBadging(output)

	if a.cfg.Verbose {
		log.Printf("[AAPT2] Command output length: %d bytes", len(output))
		if len(output) > 500 {
			log.Printf("[AAPT2] Output preview: %s...", output[:500])
		} else {
			log.Printf("[AAPT2] Output: %s", output)
		}
	} else {
		// Build a comprehensive summary of badging details
		details := fmt.Sprintf("package: %s", badging.PackageName)
		if badging.VersionName != "" {
			details += fmt.Sprintf(", version: %s", badging.VersionName)
		}
		if badging.VersionCode != "" {
			details += fmt.Sprintf(" (build %s)", badging.VersionCode)
		}
		minSDK := badging.MinSdkVersion
		if minSDK == "" {
			minSDK = "-"
		}
		targetSDK := badging.TargetSdkVersion
		if targetSDK == "" {
			targetSDK = "-"
		}
		details += fmt.Sprintf(", SDK: min %s → target %s", minSDK, targetSDK)
		if badging.ApplicationLabel != "" {
			details += fmt.Sprintf(", label: %s", badging.ApplicationLabel)
		}
		if len(badging.UsesPermissions) > 0 {
			details += fmt.Sprintf(", permissions: %d", len(badging.UsesPermissions))
		}
		if len(badging.NativeCode) > 0 {
			details += fmt.Sprintf(", archs: %s", strings.Join(badging.NativeCode, ","))
		}
		log.Printf("✓ Extracted APK metadata (%s)", details)
	}

	return badging, nil
}

// parseBadging parses the output of aapt2 dump badging command
func (a *AAPT2Extractor) parseBadging(output string) *models.AAPT2BadgingInfo {
	badging := &models.AAPT2BadgingInfo{
		RawOutput: output,
	}

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "package:") {
			badging.PackageName = extractQuotedValue(line, "name=")
			badging.VersionCode = extractQuotedValue(line, "versionCode=")
			badging.VersionName = extractQuotedValue(line, "versionName=")
			badging.PlatformBuildVersionName = extractQuotedValue(line, "platformBuildVersionName=")
			badging.PlatformBuildVersionCode = extractQuotedValue(line, "platformBuildVersionCode=")
			badging.CompileSdkVersion = extractQuotedValue(line, "compileSdkVersion=")
			badging.CompileSdkVersionCodename = extractQuotedValue(line, "compileSdkVersionCodename=")
		}

		if strings.HasPrefix(line, "sdkVersion:") {
			badging.MinSdkVersion = strings.Trim(strings.TrimPrefix(line, "sdkVersion:"), "'\"")
		}

		if strings.HasPrefix(line, "targetSdkVersion:") {
			badging.TargetSdkVersion = strings.Trim(strings.TrimPrefix(line, "targetSdkVersion:"), "'\"")
		}

		if strings.HasPrefix(line, "application-label:") {
			badging.ApplicationLabel = strings.Trim(strings.TrimPrefix(line, "application-label:"), "'\"")
		}

		if strings.HasPrefix(line, "application-icon-") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				density := strings.TrimPrefix(parts[0], "application-icon-")
				iconPath := strings.Trim(parts[1], "'\"")
				if badging.ApplicationIcons == nil {
					badging.ApplicationIcons = make(map[string]string)
				}
				badging.ApplicationIcons[density] = iconPath
			}
		}

		if strings.HasPrefix(line, "launchable-activity:") {
			badging.LaunchableActivity = extractQuotedValue(line, "name=")
		}

		if strings.HasPrefix(line, "uses-permission:") {
			permission := extractQuotedValue(line, "name=")
			if permission != "" {
				badging.UsesPermissions = append(badging.UsesPermissions, permission)
			}
		}

		if strings.HasPrefix(line, "uses-feature:") {
			feature := extractQuotedValue(line, "name=")
			if feature != "" {
				badging.UsesFeatures = append(badging.UsesFeatures, feature)
			}
		}

		if strings.HasPrefix(line, "native-code:") {
			archStr := strings.TrimPrefix(line, "native-code:")
			archStr = strings.Trim(archStr, "'\" ")
			if archStr != "" {
				badging.NativeCode = strings.Fields(archStr)
			}
		}

		if strings.HasPrefix(line, "locales:") {
			localeStr := strings.TrimPrefix(line, "locales:")
			localeStr = strings.Trim(localeStr, "'\" ")
			if localeStr != "" {
				badging.Locales = strings.Fields(localeStr)
			}
		}

		if strings.HasPrefix(line, "densities:") {
			densityStr := strings.TrimPrefix(line, "densities:")
			densityStr = strings.Trim(densityStr, "'\" ")
			if densityStr != "" {
				badging.Densities = strings.Fields(densityStr)
			}
		}

		if strings.HasPrefix(line, "supports-screens:") {
			screenStr := strings.TrimPrefix(line, "supports-screens:")
			screenStr = strings.Trim(screenStr, "'\" ")
			if screenStr != "" {
				badging.SupportsScreens = strings.Fields(screenStr)
			}
		}

		if strings.HasPrefix(line, "supports-any-density:") {
			denseStr := strings.TrimPrefix(line, "supports-any-density:")
			denseStr = strings.Trim(denseStr, "'\" ")
			if denseStr != "" {
				badging.SupportsAnyDensity = denseStr
			}
		}
	}

	return badging
}

// ExtractPackageName extracts package name using aapt2 dump packagename
func (a *AAPT2Extractor) ExtractPackageName(ctx context.Context, apkPath string) (string, error) {
	cmd := exec.CommandContext(ctx, "aapt2", "dump", "packagename", apkPath)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("aapt2 dump packagename failed: %w (stderr: %s)", err, stderr.String())
	}

	return strings.TrimSpace(stdout.String()), nil
}

// ExtractPermissions extracts permissions using aapt2 dump permissions
func (a *AAPT2Extractor) ExtractPermissions(ctx context.Context, apkPath string) ([]string, error) {
	cmd := exec.CommandContext(ctx, "aapt2", "dump", "permissions", apkPath)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if a.cfg.Verbose {
		log.Printf("[AAPT2] Executing: aapt2 dump permissions %s", apkPath)
	}

	if err := cmd.Run(); err != nil {
		if a.cfg.Verbose {
			log.Printf("[AAPT2] Command failed: %v (stderr: %s)", err, stderr.String())
		}
		return nil, fmt.Errorf("aapt2 dump permissions failed: %w (stderr: %s)", err, stderr.String())
	}

	output := stdout.String()
	if a.cfg.Verbose {
		log.Printf("[AAPT2] Permissions output length: %d bytes", len(output))
	}
	lines := strings.Split(output, "\n")
	var permissions []string

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "package:") {

			line = strings.TrimPrefix(line, "permission: ")
			permissions = append(permissions, line)
		}
	}

	if !a.cfg.Verbose && len(permissions) > 0 {
		log.Printf("✓ Found %d permissions", len(permissions))
	}

	return permissions, nil
}

// ExtractStrings extracts string resources using aapt2 dump strings
func (a *AAPT2Extractor) ExtractStrings(ctx context.Context, apkPath string) ([]string, error) {
	cmd := exec.CommandContext(ctx, "aapt2", "dump", "strings", apkPath)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if a.cfg.Verbose {
		log.Printf("[AAPT2] Executing: aapt2 dump strings %s", apkPath)
	}

	if err := cmd.Run(); err != nil {
		if a.cfg.Verbose {
			log.Printf("[AAPT2] Command failed: %v (stderr: %s)", err, stderr.String())
		}
		return nil, fmt.Errorf("aapt2 dump strings failed: %w (stderr: %s)", err, stderr.String())
	}

	output := stdout.String()
	if a.cfg.Verbose {
		log.Printf("[AAPT2] Strings output length: %d bytes, found %d lines", len(output), len(strings.Split(output, "\n")))
	}
	lines := strings.Split(output, "\n")
	var extractedStrings []string
	seen := make(map[string]bool)

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.SplitN(line, ":", 2)
		var value string
		if len(parts) == 2 {
			value = strings.TrimSpace(parts[1])
		} else {
			value = line
		}

		value = strings.Trim(value, "\"'")

		if value != "" && !seen[value] {
			seen[value] = true
			extractedStrings = append(extractedStrings, value)
		}
	}

	if !a.cfg.Verbose && len(extractedStrings) > 0 {
		log.Printf("✓ Extracted %d unique strings from APK", len(extractedStrings))
	}

	return extractedStrings, nil
}

// extractQuotedValue extracts a value from a key='value' or key="value" pattern
func extractQuotedValue(line, key string) string {

	pattern := regexp.MustCompile(key + `'([^']*)'`)
	matches := pattern.FindStringSubmatch(line)
	if len(matches) > 1 {
		return matches[1]
	}

	pattern = regexp.MustCompile(key + `"([^"]*)"`)
	matches = pattern.FindStringSubmatch(line)
	if len(matches) > 1 {
		return matches[1]
	}

	pattern = regexp.MustCompile(key + `'?([^'\s]+)'?`)
	matches = pattern.FindStringSubmatch(line)
	if len(matches) > 1 {
		return strings.Trim(matches[1], "'\"")
	}

	return ""
}
