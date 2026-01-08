package analyzer

import (
	"archive/zip"
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	models "github.com/flutterguard/flutterguard-cli/models"
)

type Decompiler struct {
	cfg        *Config
	strategies []DecompilerStrategy
}

func NewDecompiler(cfg *Config) *Decompiler {
	strategies := []DecompilerStrategy{
		NewApkDirectZipDecompiler(),
		NewJadxDecompiler(cfg),
	}

	sort.Slice(strategies, func(i, j int) bool {
		return strategies[i].Priority() > strategies[j].Priority()
	})

	return &Decompiler{
		cfg:        cfg,
		strategies: strategies,
	}
}

// DecompileWithStrategies tries multiple decompiler strategies until one succeeds
func (d *Decompiler) DecompileWithStrategies(ctx context.Context, apkPath, outputDir string) (*DecompilerResult, error) {
	var lastErr error
	var attempts []string
	var attemptDetails []models.DecompilationAttempt
	stamp := func() string { return time.Now().Format(time.RFC3339) }

	for _, strategy := range d.strategies {
		attemptLog := []string{fmt.Sprintf("[%s] Strategy %s: starting evaluation (apk=%s, output=%s)", stamp(), strategy.Name(), apkPath, outputDir)}
		canHandle, err := strategy.CanHandle(apkPath)
		if err != nil {
			if d.cfg.Verbose {
				log.Printf("Strategy %s cannot handle APK: %v", strategy.Name(), err)
			}
			lastErr = err
			attempts = append(attempts, fmt.Sprintf("%s (unavailable)", strategy.Name()))
			attemptLog = append(attemptLog, fmt.Sprintf("[%s] Compatibility check failed: %v", stamp(), err))
			attemptDetails = append(attemptDetails, models.DecompilationAttempt{Strategy: strategy.Name(), Success: false, Error: err.Error(), Logs: attemptLog})
			continue
		}

		if !canHandle {
			if d.cfg.Verbose {
				log.Printf("Strategy %s reports it cannot handle this APK", strategy.Name())
			}
			attempts = append(attempts, fmt.Sprintf("%s (incompatible)", strategy.Name()))
			attemptLog = append(attemptLog, fmt.Sprintf("[%s] Strategy marked APK as incompatible", stamp()))
			attemptDetails = append(attemptDetails, models.DecompilationAttempt{Strategy: strategy.Name(), Success: false, Error: "incompatible with APK", Logs: attemptLog})
			continue
		}

		if d.cfg.Verbose {
			log.Printf("Attempting decompilation with: %s", strategy.Name())
		}
		attempts = append(attempts, strategy.Name())
		attemptLog = append(attemptLog, fmt.Sprintf("[%s] Strategy ready; invoking decompile", stamp()))
		if cmdSummary := d.describeStrategyCommand(strategy, apkPath, outputDir); cmdSummary != "" {
			attemptLog = append(attemptLog, fmt.Sprintf("[%s] Command: %s", stamp(), cmdSummary))
		}
		attemptDetails = append(attemptDetails, models.DecompilationAttempt{Strategy: strategy.Name(), Success: false, Logs: attemptLog})

		err = strategy.Decompile(ctx, apkPath, outputDir)
		if err == nil {
			if d.cfg.Verbose {
				log.Printf("Successfully decompiled using: %s", strategy.Name())
			}
			attemptDetails[len(attemptDetails)-1].Success = true
			attemptDetails[len(attemptDetails)-1].Logs = append(attemptDetails[len(attemptDetails)-1].Logs, fmt.Sprintf("[%s] Decompilation succeeded", stamp()))
			return &DecompilerResult{
				Strategy:  strategy.Name(),
				Success:   true,
				Error:     nil,
				OutputDir: outputDir,
				Attempts:  attemptDetails,
			}, nil
		}

		if d.cfg.Verbose {
			log.Printf("Strategy %s failed: %v", strategy.Name(), err)
		}
		attemptDetails[len(attemptDetails)-1].Error = err.Error()
		attemptDetails[len(attemptDetails)-1].Logs = append(attemptDetails[len(attemptDetails)-1].Logs, fmt.Sprintf("[%s] Decompilation failed: %v", stamp(), err))
		lastErr = err
	}

	if lastErr == nil {
		lastErr = fmt.Errorf("no decompiler strategy could handle this APK")
	}

	return &DecompilerResult{
		Strategy:  strings.Join(attempts, ", "),
		Success:   false,
		Error:     fmt.Errorf("all decompilation strategies failed (tried: %s): %w", strings.Join(attempts, ", "), lastErr),
		OutputDir: "",
		Attempts:  attemptDetails,
	}, lastErr
}

func (d *Decompiler) describeStrategyCommand(strategy DecompilerStrategy, apkPath, outputDir string) string {
	switch strategy.(type) {
	case *JadxDecompiler:
		return fmt.Sprintf("jadx -d %s -j 1 --no-res --no-imports --deobf-use-sourcename --deobf-min %s", outputDir, apkPath)
	case *ApkDirectZipDecompiler:
		return "zip extraction only (no external command)"
	default:
		return ""
	}
}

// FindLibAppSO finds the libapp.so file in the decompiled APK
func (d *Decompiler) FindLibAppSO(decompDir string) (string, error) {
	var libappPath string

	err := filepath.Walk(decompDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && info.Name() == "libapp.so" {
			libappPath = path
			return io.EOF
		}
		return nil
	})

	if err != nil && err != io.EOF {
		return "", err
	}

	if libappPath == "" {
		return "", fmt.Errorf("libapp.so not found in decompiled APK")
	}

	return libappPath, nil
}

// ValidateAPK checks if a file is a valid APK
func ValidateAPK(filePath string) error {

	if !strings.HasSuffix(strings.ToLower(filePath), ".apk") {
		return fmt.Errorf("file is not an APK")
	}

	info, err := os.Stat(filePath)
	if err != nil {
		return fmt.Errorf("file does not exist: %w", err)
	}

	if !info.Mode().IsRegular() {
		return fmt.Errorf("not a regular file")
	}

	if info.Size() == 0 {
		return fmt.Errorf("APK file is empty")
	}

	return nil
}

// IsFlutterAPK performs a lightweight check to confirm the APK looks like a Flutter app.
// It searches for common Flutter artifacts such as flutter_assets, libapp.so, or libflutter.so.
func IsFlutterAPK(filePath string) (bool, error) {
	r, err := zip.OpenReader(filePath)
	if err != nil {
		return false, fmt.Errorf("unable to open apk: %w", err)
	}
	defer r.Close()

	var hasFlutterAssets bool
	var hasLibApp bool
	var hasLibFlutter bool

	for _, f := range r.File {
		name := strings.ToLower(f.Name)

		if strings.HasPrefix(name, "assets/flutter_assets") || strings.HasPrefix(name, "flutter_assets") || strings.Contains(name, "/flutter_assets/") {
			hasFlutterAssets = true
		}
		if strings.HasSuffix(name, "libapp.so") {
			hasLibApp = true
		}
		if strings.HasSuffix(name, "libflutter.so") {
			hasLibFlutter = true
		}

		if hasFlutterAssets || hasLibApp || hasLibFlutter {
			return true, nil
		}
	}

	return false, nil
}

// ExtractManifestPermissions extracts permissions from AndroidManifest.xml
func (d *Decompiler) ExtractManifestPermissions(decompDir string) []models.Permission {
	manifestPath := filepath.Join(decompDir, "resources", "AndroidManifest.xml")

	data, err := os.ReadFile(manifestPath)
	if err != nil {

		manifestPath = filepath.Join(decompDir, "AndroidManifest.xml")
		data, err = os.ReadFile(manifestPath)
		if err != nil {
			return []models.Permission{}
		}
	}

	// Parse XML
	type Manifest struct {
		UsesPermission []struct {
			Name string `xml:"name,attr"`
		} `xml:"uses-permission"`
	}

	var manifest Manifest
	if err := xml.Unmarshal(data, &manifest); err != nil {

		return d.extractPermissionsRegex(string(data))
	}

	var permissions []models.Permission
	for _, perm := range manifest.UsesPermission {
		permission := models.Permission{
			Name:      perm.Name,
			Dangerous: isDangerousPermission(perm.Name),
		}
		permission.Description = getPermissionDescription(perm.Name)
		permissions = append(permissions, permission)
	}

	if len(permissions) == 0 {
		return d.extractPermissionsRegex(string(data))
	}

	return permissions
}

func (d *Decompiler) extractPermissionsRegex(content string) []models.Permission {
	re := regexp.MustCompile(`android:name="(android\.permission\.[^"]+)"`)
	matches := re.FindAllStringSubmatch(content, -1)

	var permissions []models.Permission
	seen := make(map[string]bool)

	for _, match := range matches {
		if len(match) > 1 && !seen[match[1]] {
			seen[match[1]] = true
			permissions = append(permissions, models.Permission{
				Name:        match[1],
				Dangerous:   isDangerousPermission(match[1]),
				Description: getPermissionDescription(match[1]),
			})
		}
	}

	return permissions
}

// ExtractAppMetadata extracts app metadata from manifest and other sources
func (d *Decompiler) ExtractAppMetadata(decompDir, apkPath string, libappContent string) models.AppMetadata {
	metadata := models.AppMetadata{}

	if info, err := os.Stat(apkPath); err == nil {
		metadata.APKSize = info.Size()
	}

	manifestPath := filepath.Join(decompDir, "resources", "AndroidManifest.xml")
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		manifestPath = filepath.Join(decompDir, "AndroidManifest.xml")
		data, _ = os.ReadFile(manifestPath)
	}

	if len(data) > 0 {
		content := string(data)

		if re := regexp.MustCompile(`package="([^"]+)"`); re.MatchString(content) {
			if match := re.FindStringSubmatch(content); len(match) > 1 {
				metadata.PackageName = match[1]
			}
		}

		if re := regexp.MustCompile(`android:versionName="([^"]+)"`); re.MatchString(content) {
			if match := re.FindStringSubmatch(content); len(match) > 1 {
				metadata.VersionName = match[1]
			}
		}

		if re := regexp.MustCompile(`android:versionCode="([^"]+)"`); re.MatchString(content) {
			if match := re.FindStringSubmatch(content); len(match) > 1 {
				metadata.VersionCode = match[1]
			}
		}

		if re := regexp.MustCompile(`android:minSdkVersion="([^"]+)"`); re.MatchString(content) {
			if match := re.FindStringSubmatch(content); len(match) > 1 {
				metadata.MinSDKVersion = match[1]
			}
		}

		if re := regexp.MustCompile(`android:targetSdkVersion="([^"]+)"`); re.MatchString(content) {
			if match := re.FindStringSubmatch(content); len(match) > 1 {
				metadata.TargetSDK = match[1]
			}
		}
	}

	if flutterRe := regexp.MustCompile(`Flutter\s+([0-9]+\.[0-9]+\.[0-9]+)`); flutterRe.MatchString(libappContent) {
		if match := flutterRe.FindStringSubmatch(libappContent); len(match) > 1 {
			metadata.FlutterVersion = match[1]
		}
	}

	if dartRe := regexp.MustCompile(`Dart\s+([0-9]+\.[0-9]+\.[0-9]+)`); dartRe.MatchString(libappContent) {
		if match := dartRe.FindStringSubmatch(libappContent); len(match) > 1 {
			metadata.DartVersion = match[1]
		}
	}

	if info, err := os.Stat(apkPath); err == nil {
		metadata.BuildTimestamp = info.ModTime().Format("2006-01-02 15:04:05 MST")
	}

	metadata.SigningScheme = d.detectSigningScheme(decompDir)

	metadata.IsDebugBuild = d.IsDebuggable(decompDir) || strings.Contains(strings.ToLower(apkPath), "debug")

	metadata.SupportedABIs = d.detectABIs(decompDir)

	if engineRe := regexp.MustCompile(`engine\s+([a-f0-9]{7,40})`); engineRe.MatchString(libappContent) {
		if match := engineRe.FindStringSubmatch(libappContent); len(match) > 1 {
			metadata.FlutterEngineHash = match[1]
		}
	}

	metadata.ImpellerEnabled = strings.Contains(libappContent, "impeller") || strings.Contains(libappContent, "Impeller")

	metadata.ExtractedTexts = d.extractTexts(libappContent)

	metadata.MonetizationSDKs = d.detectMonetizationSDKs(libappContent)

	return metadata
}

func (d *Decompiler) detectSigningScheme(decompDir string) string {

	metaInfPath := findMetaINFDirectory(decompDir)
	if metaInfPath == "" {
		return "unknown"
	}

	schemes := []string{}

	if files, err := filepath.Glob(filepath.Join(metaInfPath, "*.RSA")); err == nil && len(files) > 0 {
		schemes = append(schemes, "v1")
	} else if files, err := filepath.Glob(filepath.Join(metaInfPath, "*.DSA")); err == nil && len(files) > 0 {
		schemes = append(schemes, "v1")
	}

	if _, err := os.Stat(filepath.Join(metaInfPath, "CERT.SF")); err == nil {
		schemes = append(schemes, "v2+")
	}

	if len(schemes) == 0 {
		return "Unknown"
	}
	return strings.Join(schemes, ", ")
}

func (d *Decompiler) detectABIs(decompDir string) []string {
	var abis []string
	libPath := filepath.Join(decompDir, "lib")
	if _, err := os.Stat(libPath); os.IsNotExist(err) {
		return abis
	}

	entries, err := os.ReadDir(libPath)
	if err != nil {
		return abis
	}

	for _, e := range entries {
		if e.IsDir() {
			abis = append(abis, e.Name())
		}
	}
	return abis
}

func (d *Decompiler) extractTexts(content string) []string {

	re := regexp.MustCompile(`[a-zA-Z][a-zA-Z0-9\s.,;:!?'"()-]{6,100}`)
	matches := re.FindAllString(content, -1)

	seen := make(map[string]bool)
	var texts []string

	boilerplatePatterns := []string{
		"package ", "import ", "class ", "public ", "private ", "protected ",
		"static ", "final ", "void ", "return ", "new ", "super",
		"extends ", "implements ", "interface ", "enum ", "throws ",
		"android.", "java.", "kotlin.", "com.", "org.", "net.",
		"0x00", "0x", "0000", "1111", "ffff",
		"BuildConfig", "R.", "androidx", "runtime", "annotation",
		"annotation Retention", "annotation Target", "deprecated",
	}

	for _, m := range matches {
		cleaned := strings.TrimSpace(m)
		if cleaned == "" || seen[cleaned] {
			continue
		}

		if len(cleaned) < 5 {
			continue
		}

		if d.isRepeatedChars(cleaned) {
			continue
		}

		isBoilerplate := false
		cleanedLower := strings.ToLower(cleaned)
		for _, pattern := range boilerplatePatterns {
			if strings.Contains(cleanedLower, strings.ToLower(pattern)) {
				isBoilerplate = true
				break
			}
		}
		if isBoilerplate {
			continue
		}

		if !strings.Contains(cleaned, " ") && len(cleaned) < 10 {
			continue
		}

		digitCount := 0
		for _, c := range cleaned {
			if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') {
				digitCount++
			}
		}
		if float64(digitCount)/float64(len(cleaned)) > 0.6 {
			continue
		}

		seen[cleaned] = true
		texts = append(texts, cleaned)
		if len(texts) >= 50 {
			break
		}
	}

	return texts
}

// isRepeatedChars checks if a string is mostly repeated characters
func (d *Decompiler) isRepeatedChars(s string) bool {
	if len(s) == 0 {
		return false
	}
	first := rune(s[0])
	count := 0
	for _, c := range s {
		if c == first {
			count++
		}
	}
	return count > len(s)/2
}

func (d *Decompiler) detectMonetizationSDKs(content string) []string {
	monetization := []string{
		"admob", "AdMob", "google_mobile_ads",
		"facebook_audience", "FAN",
		"unity_ads", "UnityAds",
		"applovin", "AppLovin",
		"ironSource", "ironsource",
		"vungle", "Vungle",
		"chartboost", "Chartboost",
		"mopub", "MoPub",
		"inmobi", "InMobi",
		"tapjoy", "Tapjoy",
	}

	var detected []string
	contentLower := strings.ToLower(content)
	for _, sdk := range monetization {
		if strings.Contains(contentLower, strings.ToLower(sdk)) {
			detected = append(detected, sdk)
		}
	}

	seen := make(map[string]bool)
	var unique []string
	for _, s := range detected {
		lower := strings.ToLower(s)
		if !seen[lower] {
			seen[lower] = true
			unique = append(unique, s)
		}
	}
	return unique
}

func isDangerousPermission(permission string) bool {
	dangerous := []string{
		"READ_CALENDAR", "WRITE_CALENDAR",
		"CAMERA",
		"READ_CONTACTS", "WRITE_CONTACTS", "GET_ACCOUNTS",
		"ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION",
		"RECORD_AUDIO",
		"READ_PHONE_STATE", "READ_PHONE_NUMBERS", "CALL_PHONE",
		"READ_CALL_LOG", "WRITE_CALL_LOG", "ADD_VOICEMAIL",
		"USE_SIP", "PROCESS_OUTGOING_CALLS",
		"BODY_SENSORS",
		"SEND_SMS", "RECEIVE_SMS", "READ_SMS",
		"RECEIVE_WAP_PUSH", "RECEIVE_MMS",
		"READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE",
		"ACCESS_MEDIA_LOCATION",
	}

	for _, d := range dangerous {
		if strings.Contains(permission, d) {
			return true
		}
	}
	return false
}

func getPermissionDescription(permission string) string {
	descriptions := map[string]string{
		"INTERNET":               "Access the internet",
		"ACCESS_NETWORK_STATE":   "View network connections",
		"CAMERA":                 "Take pictures and videos",
		"READ_EXTERNAL_STORAGE":  "Read from external storage",
		"WRITE_EXTERNAL_STORAGE": "Write to external storage",
		"ACCESS_FINE_LOCATION":   "Access precise location",
		"ACCESS_COARSE_LOCATION": "Access approximate location",
		"READ_CONTACTS":          "Read contacts",
		"WRITE_CONTACTS":         "Modify contacts",
		"READ_PHONE_STATE":       "Read phone status and identity",
		"CALL_PHONE":             "Make phone calls",
		"RECORD_AUDIO":           "Record audio",
		"SEND_SMS":               "Send SMS messages",
		"RECEIVE_SMS":            "Receive SMS messages",
		"READ_SMS":               "Read SMS messages",
		"VIBRATE":                "Control vibration",
		"WAKE_LOCK":              "Prevent phone from sleeping",
		"ACCESS_WIFI_STATE":      "View Wi-Fi connections",
		"CHANGE_WIFI_STATE":      "Connect and disconnect from Wi-Fi",
		"BLUETOOTH":              "Pair with Bluetooth devices",
		"BLUETOOTH_ADMIN":        "Control Bluetooth settings",
		"GET_ACCOUNTS":           "Find accounts on the device",
		"USE_CREDENTIALS":        "Use accounts on the device",
		"MANAGE_ACCOUNTS":        "Add or remove accounts",
		"READ_CALENDAR":          "Read calendar events",
		"WRITE_CALENDAR":         "Add or modify calendar events",
	}

	for key, desc := range descriptions {
		if strings.Contains(permission, key) {
			return desc
		}
	}

	return ""
}

// IsDebuggable reads AndroidManifest and returns whether debuggable is true
func (d *Decompiler) IsDebuggable(decompDir string) bool {
	manifestPath := filepath.Join(decompDir, "resources", "AndroidManifest.xml")
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		manifestPath = filepath.Join(decompDir, "AndroidManifest.xml")
		data, err = os.ReadFile(manifestPath)
		if err != nil {
			return false
		}
	}
	content := string(data)
	return strings.Contains(content, "android:debuggable=\"true\"")
}

// FindFirebaseConfig attempts to read google-services.json and return minimal info
func (d *Decompiler) FindFirebaseConfig(decompDir string) *models.FirebaseInfo {
	var foundPath string
	_ = filepath.Walk(decompDir, func(path string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() && strings.EqualFold(info.Name(), "google-services.json") {
			foundPath = path
			return io.EOF
		}
		return nil
	})
	if foundPath == "" {
		return nil
	}
	b, err := os.ReadFile(foundPath)
	if err != nil {
		return &models.FirebaseInfo{Detected: true, Indicators: []string{"google-services.json present"}}
	}
	type gs struct {
		ProjectInfo struct {
			ProjectID     string `json:"project_id"`
			StorageBucket string `json:"storage_bucket"`
		} `json:"project_info"`
		Client []struct {
			ApiKey []struct {
				CurrentKey string `json:"current_key"`
			} `json:"api_key"`
		} `json:"client"`
	}
	var g gs
	_ = json.Unmarshal(b, &g)
	info := &models.FirebaseInfo{Detected: true, Indicators: []string{"google-services.json present"}}
	info.ProjectID = g.ProjectInfo.ProjectID
	info.StorageBucket = g.ProjectInfo.StorageBucket
	if len(g.Client) > 0 && len(g.Client[0].ApiKey) > 0 {
		k := g.Client[0].ApiKey[0].CurrentKey
		if len(k) > 8 {
			info.APIKeyMasked = k[:6] + "***" + k[len(k)-2:]
		} else {
			info.APIKeyMasked = k
		}
	}

	info.Endpoints = []string{"firebaseio.com", "firebasestorage.googleapis.com"}
	return info
}
