package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/flutterguard/flutterguard-cli/ai"
	"github.com/flutterguard/flutterguard-cli/models"
)

type aiSummaryReport struct {
	GeneratedAt   string         `json:"generated_at"`
	Provider      string         `json:"provider"`
	Model         string         `json:"model,omitempty"`
	SystemPrompt  string         `json:"system_prompt"`
	Findings      []string       `json:"findings"`
	Counts        map[string]int `json:"counts"`
	Summary       string         `json:"summary"`
	UsedAIService bool           `json:"used_ai_service"`
	Error         string         `json:"error,omitempty"`
}

func writeUnifiedScanReport(results *models.Results, config *CLIConfig, apkPath string) (string, error) {
	baseOutDir := config.OutputDir
	if baseOutDir == "" {
		baseOutDir = "results"
	}

	apkName := strings.TrimSuffix(filepath.Base(apkPath), filepath.Ext(apkPath))
	apkName = sanitizeFileName(apkName)
	if strings.TrimSpace(apkName) == "" {
		apkName = "scan"
	}

	reportDir := filepath.Join(baseOutDir, apkName)
	if err := os.RemoveAll(reportDir); err != nil {
		return "", fmt.Errorf("failed to reset report directory: %w", err)
	}
	if err := os.MkdirAll(filepath.Join(reportDir, "files"), 0755); err != nil {
		return "", fmt.Errorf("failed to create files directory: %w", err)
	}
	if err := os.MkdirAll(filepath.Join(reportDir, "resources"), 0755); err != nil {
		return "", fmt.Errorf("failed to create resources directory: %w", err)
	}

	cloned := *results
	sourceToDest := make(map[string]string)
	iconPath := results.AppInfo.AppIconPath

	mapFiles := func(items []models.FileInfo, folder string) ([]models.FileInfo, error) {
		out := make([]models.FileInfo, 0, len(items))
		for _, item := range items {
			updated, err := copyAndRebaseFileInfo(item, folder, reportDir, sourceToDest)
			if err != nil {
				return nil, err
			}
			if updated.Path == "" {
				continue
			}
			out = append(out, updated)
		}
		return out, nil
	}

	var err error
	cloned.EnvFiles, err = mapFiles(results.EnvFiles, "files")
	if err != nil {
		return "", err
	}
	cloned.ConfigFiles, err = mapFiles(results.ConfigFiles, "files")
	if err != nil {
		return "", err
	}
	cloned.ContentFiles, err = mapFiles(results.ContentFiles, "files")
	if err != nil {
		return "", err
	}
	cloned.VisualAssets, err = mapFiles(results.VisualAssets, "resources")
	if err != nil {
		return "", err
	}

	if iconPath != "" {
		if rel, ok := sourceToDest[iconPath]; ok {
			cloned.AppInfo.AppIconPath = rel
		}
	}

	if results.DecompiledFolderPath != "" {
		destRel, err := copyIntoReport(results.DecompiledFolderPath, "files", reportDir, sourceToDest)
		if err != nil {
			return "", err
		}
		cloned.DecompiledFolderPath = destRel
	}

	cloned.DecompiledDirPath = ""

	resultsJSONPath := filepath.Join(reportDir, "results.json")
	jsonData, err := json.MarshalIndent(&cloned, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal results.json: %w", err)
	}
	if err := os.WriteFile(resultsJSONPath, jsonData, 0644); err != nil {
		return "", fmt.Errorf("failed to write results.json: %w", err)
	}

	if config.EnableAIRemediation {
		if err := writeAISummaryFiles(reportDir, &cloned, config); err != nil {
			return "", err
		}
	}

	return reportDir, nil
}

func copyAndRebaseFileInfo(
	item models.FileInfo,
	targetRoot string,
	reportDir string,
	sourceToDest map[string]string,
) (models.FileInfo, error) {
	if strings.TrimSpace(item.Path) == "" {
		return item, nil
	}
	destRel, err := copyIntoReport(item.Path, targetRoot, reportDir, sourceToDest)
	if err != nil {
		return models.FileInfo{}, err
	}

	item.Path = destRel
	item.Name = filepath.Base(destRel)
	if st, statErr := os.Stat(filepath.Join(reportDir, filepath.FromSlash(destRel))); statErr == nil {
		item.Size = st.Size()
	}

	return item, nil
}

func copyIntoReport(
	srcPath string,
	targetRoot string,
	reportDir string,
	sourceToDest map[string]string,
) (string, error) {
	cleanSrc := filepath.Clean(srcPath)
	if rel, ok := sourceToDest[cleanSrc]; ok {
		return rel, nil
	}

	if _, err := os.Stat(cleanSrc); err != nil {
		return "", fmt.Errorf("failed to stat extracted artifact %s: %w", cleanSrc, err)
	}

	baseName := sanitizeFileName(filepath.Base(cleanSrc))
	if baseName == "" || baseName == "." || baseName == "/" {
		baseName = "artifact"
	}

	destRel := filepath.ToSlash(filepath.Join(targetRoot, baseName))
	destAbs := filepath.Join(reportDir, filepath.FromSlash(destRel))
	destAbs = ensureUniquePath(destAbs)
	destRel, err := filepath.Rel(reportDir, destAbs)
	if err != nil {
		return "", fmt.Errorf("failed to derive report-relative path for %s: %w", srcPath, err)
	}
	destRel = filepath.ToSlash(destRel)

	if err := os.MkdirAll(filepath.Dir(destAbs), 0755); err != nil {
		return "", fmt.Errorf("failed to create destination directory for %s: %w", srcPath, err)
	}

	if err := copyFileRaw(cleanSrc, destAbs); err != nil {
		return "", fmt.Errorf("failed to copy extracted artifact %s: %w", srcPath, err)
	}

	sourceToDest[cleanSrc] = destRel
	return destRel, nil
}

func ensureUniquePath(path string) string {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return path
	}

	ext := filepath.Ext(path)
	base := strings.TrimSuffix(path, ext)
	for i := 1; ; i++ {
		candidate := fmt.Sprintf("%s_%d%s", base, i, ext)
		if _, err := os.Stat(candidate); os.IsNotExist(err) {
			return candidate
		}
	}
}

func copyFileRaw(srcPath, destPath string) error {
	data, err := os.ReadFile(srcPath)
	if err != nil {
		return err
	}
	return os.WriteFile(destPath, data, 0644)
}

func writeAISummaryFiles(reportDir string, results *models.Results, config *CLIConfig) error {
	systemPrompt := ai.SystemPrompt() + "\nAdditionally, summarize the overall APK scan findings and highlight vulnerabilities, risk level, and top remediation priorities."
	findings, counts := deriveVulnerabilitySnapshot(results)

	aiCfg := &ai.AIConfig{
		Enabled:  true,
		Provider: ai.ProviderType(config.AIProvider),
		APIKey:   config.AIKey,
		BaseURL:  config.AIBaseURL,
		Model:    config.AIModel,
	}
	client, err := ai.NewAIClient(aiCfg)
	if err != nil {
		return fmt.Errorf("failed to initialize AI remediation client: %w", err)
	}

	usedAIService := false
	aiSummary := ""
	aiErr := ""
	rawResults, err := json.Marshal(results)
	if err != nil {
		return fmt.Errorf("failed to build AI summary input: %w", err)
	}
	promptContext := fmt.Sprintf("System prompt:\n%s\n\nFull scan results JSON:\n%s", systemPrompt, string(rawResults))
	aiSummary, err = client.ExplainFinding("apk_security_summary", promptContext)
	if err != nil {
		aiErr = err.Error()
	} else {
		usedAIService = strings.TrimSpace(aiSummary) != ""
	}

	if strings.TrimSpace(aiSummary) == "" {
		aiSummary = fallbackAISummary(results, findings, counts)
		usedAIService = false
	}

	report := aiSummaryReport{
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
		Provider:      config.AIProvider,
		Model:         config.AIModel,
		SystemPrompt:  systemPrompt,
		Findings:      findings,
		Counts:        counts,
		Summary:       aiSummary,
		UsedAIService: usedAIService,
		Error:         aiErr,
	}

	summaryJSON, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal ai summary json: %w", err)
	}
	if err := os.WriteFile(filepath.Join(reportDir, "ai_summary.json"), summaryJSON, 0644); err != nil {
		return fmt.Errorf("failed to write ai_summary.json: %w", err)
	}
	if err := os.WriteFile(filepath.Join(reportDir, "ai_summary.md"), []byte(aiSummary+"\n"), 0644); err != nil {
		return fmt.Errorf("failed to write ai_summary.md: %w", err)
	}
	return nil
}

func deriveVulnerabilitySnapshot(results *models.Results) ([]string, map[string]int) {
	var findings []string
	counts := map[string]int{
		"hardcoded_keys":           len(results.HardcodedKeys),
		"http_urls":                len(results.URLs.HTTP),
		"dangerous_permissions":    results.Summary.DangerousPermissions,
		"api_endpoints":            len(results.APIEndpoints),
		"sql_commands":             len(results.SQLCommands),
		"sqlite_databases":         len(results.SQLiteDatabases),
		"services_detected":        len(results.Services),
		"high_privacy_impact_sdks": 0,
	}

	if results.SDKAnalysis != nil {
		counts["high_privacy_impact_sdks"] = results.SDKAnalysis.HighPrivacyImpactCount
	}

	if len(results.HardcodedKeys) > 0 {
		findings = append(findings, "Hardcoded keys/secrets detected")
	}
	if len(results.URLs.HTTP) > 0 {
		findings = append(findings, "Cleartext HTTP URLs detected")
	}
	if results.DebugInfo != nil && results.DebugInfo.ManifestDebuggable {
		findings = append(findings, "Debuggable flag appears enabled")
	}
	if results.Summary.DangerousPermissions > 0 {
		findings = append(findings, "Dangerous Android permissions requested")
	}
	if len(results.SQLCommands) > 0 {
		findings = append(findings, "Potential SQL usage detected; review injection safety")
	}
	if len(results.SQLiteDatabases) > 0 {
		findings = append(findings, "SQLite databases detected; ensure encryption at rest")
	}
	if results.NetworkSecurity != nil && results.NetworkSecurity.CleartextAllowed {
		findings = append(findings, "Network security allows cleartext traffic")
	}
	if results.Obfuscation != nil && !results.Obfuscation.LikelyObfuscated {
		findings = append(findings, "Obfuscation appears weak or absent")
	}
	if len(findings) == 0 {
		findings = append(findings, "No high-signal vulnerability indicators were detected by static checks")
	}
	return findings, counts
}

func fallbackAISummary(results *models.Results, findings []string, counts map[string]int) string {
	var b strings.Builder
	b.WriteString("# AI Security Summary\n\n")
	b.WriteString("## Findings\n")
	for _, finding := range findings {
		b.WriteString("- ")
		b.WriteString(finding)
		b.WriteString("\n")
	}
	b.WriteString("\n## Vulnerability Snapshot\n")
	for k, v := range counts {
		b.WriteString(fmt.Sprintf("- %s: %d\n", strings.ReplaceAll(k, "_", " "), v))
	}
	b.WriteString("\n## Prioritized Actions\n")
	b.WriteString("- Remove hardcoded keys and move secret handling to a backend.\n")
	b.WriteString("- Enforce HTTPS-only traffic and tighten network security config.\n")
	b.WriteString("- Minimize dangerous permissions and verify least-privilege access.\n")
	b.WriteString("- Audit SQL/database handling for injection and data-at-rest encryption.\n")
	b.WriteString(fmt.Sprintf("- Review all %d detected service integrations for data privacy impact.\n", len(results.Services)))
	return b.String()
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
