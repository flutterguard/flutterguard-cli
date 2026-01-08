package analyzer

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	models "github.com/flutterguard/flutterguard-cli/models"
)

// detectNetworkSecurity analyzes network security configuration
func (a *Analyzer) detectNetworkSecurity(decompDir string) *models.NetworkSecurityConfig {
	configPath := filepath.Join(decompDir, "res", "xml", "network_security_config.xml")
	content, err := os.ReadFile(configPath)
	if err != nil {
		return nil
	}

	config := &models.NetworkSecurityConfig{
		ConfigFound: true,
		RawXML:      string(content),
	}

	contentStr := strings.ToLower(string(content))

	if strings.Contains(contentStr, "cleartexttrafficpermitted=\"true\"") {
		config.CleartextAllowed = true
		config.Risks = append(config.Risks, "Cleartext (HTTP) traffic is permitted - data can be intercepted")
	}

	if strings.Contains(contentStr, "<pin-set>") || strings.Contains(contentStr, "<pin ") {
		config.CertificatePinning = true
		config.SecurityFeatures = append(config.SecurityFeatures, "Certificate pinning enabled")
	}

	if strings.Contains(contentStr, "<trust-anchors>") {
		if strings.Contains(contentStr, "user") {
			config.TrustsUserCerts = true
			config.Risks = append(config.Risks, "User-installed certificates are trusted - vulnerable to MITM attacks")
		}
		if strings.Contains(contentStr, "system") {
			config.TrustsSystemCerts = true
		}
	}

	domainRegex := regexp.MustCompile(`<domain[^>]*>([^<]+)</domain>`)
	for _, match := range domainRegex.FindAllStringSubmatch(string(content), -1) {
		if len(match) > 1 {
			config.ConfiguredDomains = append(config.ConfiguredDomains, match[1])
		}
	}

	return config
}

// detectDataStorage analyzes data storage patterns and risks
func (a *Analyzer) detectDataStorage(contentStr string) *models.DataStorageAnalysis {
	analysis := &models.DataStorageAnalysis{}

	patterns := map[string]struct {
		desc     string
		isSecure bool
		isRisky  bool
	}{
		"SharedPreferences":           {"SharedPreferences usage detected", false, false},
		"getSharedPreferences":        {"Shared preferences access", false, false},
		"MODE_PRIVATE":                {"Private storage mode", true, false},
		"MODE_WORLD_READABLE":         {"⚠️ World-readable storage (deprecated, insecure)", false, true},
		"MODE_WORLD_WRITEABLE":        {"⚠️ World-writeable storage (deprecated, insecure)", false, true},
		"openFileOutput":              {"File output operations", false, false},
		"getExternalStorageDirectory": {"External storage access", false, false},
		"getExternalFilesDir":         {"External files directory access", false, false},
		"FileProvider":                {"FileProvider usage (secure file sharing)", true, false},
		"sqlite":                      {"SQLite database usage", false, false},
		"Room":                        {"Room database usage", false, false},
		"realm":                       {"Realm database usage", false, false},
		"EncryptedSharedPreferences":  {"✓ Encrypted SharedPreferences (secure)", true, false},
		"EncryptedFile":               {"✓ Encrypted File API (secure)", true, false},
		"KeyStore":                    {"Android KeyStore usage", true, false},
		"Cipher":                      {"Encryption operations", true, false},
		"SecretKey":                   {"Secret key operations", true, false},
	}

	for pattern, info := range patterns {
		if strings.Contains(contentStr, pattern) {
			analysis.Patterns = append(analysis.Patterns, models.StoragePattern{
				Type:        pattern,
				Description: info.desc,
				IsSecure:    info.isSecure,
				IsRisky:     info.isRisky,
			})
		}
	}

	if strings.Contains(contentStr, "SQLCipher") || strings.Contains(contentStr, "encrypted") {
		analysis.DatabaseEncryption = true
		analysis.SecurityNotes = append(analysis.SecurityNotes, "Database encryption detected")
	}

	if strings.Contains(contentStr, "allowBackup=\"true\"") {
		analysis.BackupAllowed = true
		analysis.SecurityNotes = append(analysis.SecurityNotes, "App data backup is allowed - sensitive data may be extracted")
	}

	return analysis
}

// detectWebViewSecurity analyzes WebView usage and security
func (a *Analyzer) detectWebViewSecurity(contentStr string) *models.WebViewSecurityAnalysis {
	if !strings.Contains(contentStr, "WebView") {
		return nil
	}

	analysis := &models.WebViewSecurityAnalysis{
		WebViewDetected: true,
	}

	risks := []struct {
		pattern string
		risk    string
	}{
		{"setJavaScriptEnabled(true)", "JavaScript enabled in WebView"},
		{"setAllowFileAccess(true)", "File access allowed in WebView"},
		{"setAllowFileAccessFromFileURLs(true)", "File access from file URLs allowed (vulnerable to local file disclosure)"},
		{"setAllowUniversalAccessFromFileURLs(true)", "Universal access from file URLs (high risk)"},
		{"addJavascriptInterface", "JavaScript interface exposed (potential XSS/RCE risk)"},
		{"setMixedContentMode", "Mixed content handling configured"},
		{"setSavePassword(true)", "Password saving enabled (deprecated, insecure)"},
		{"setGeolocationEnabled", "Geolocation access configured"},
	}

	for _, r := range risks {
		if strings.Contains(contentStr, r.pattern) {
			isHighRisk := strings.Contains(r.risk, "high risk") ||
				strings.Contains(r.risk, "vulnerable") ||
				strings.Contains(r.risk, "insecure")

			analysis.Settings = append(analysis.Settings, models.WebViewSetting{
				Setting:     r.pattern,
				Description: r.risk,
				IsRisky:     isHighRisk,
			})
		}
	}

	secureSettings := []string{
		"setAllowFileAccess(false)",
		"setJavaScriptEnabled(false)",
		"setSafeBrowsingEnabled(true)",
	}

	for _, setting := range secureSettings {
		if strings.Contains(contentStr, setting) {
			analysis.SecurityFeatures = append(analysis.SecurityFeatures, setting)
		}
	}

	return analysis
}

// detectObfuscation analyzes code obfuscation techniques
func (a *Analyzer) detectObfuscation(contentStr string, decompDir string) *models.ObfuscationAnalysis {
	analysis := &models.ObfuscationAnalysis{}

	mappingPath := filepath.Join(decompDir, "mapping.txt")
	if _, err := os.Stat(mappingPath); err == nil {
		analysis.ProGuardDetected = true
		analysis.MappingFileFound = true
	}

	shortNamePattern := regexp.MustCompile(`\b[a-z]\.[a-z]\.[a-z]\b`)
	shortNames := shortNamePattern.FindAllString(contentStr, -1)
	if len(shortNames) > 100 {
		analysis.LikelyObfuscated = true
		analysis.ShortClassNames = len(shortNames)
		analysis.Indicators = append(analysis.Indicators, fmt.Sprintf("Found %d short class names (a.b.c pattern)", len(shortNames)))
	}

	stringEncPatterns := []string{
		"decrypt",
		"deobfuscate",
		"xor",
		"base64",
	}

	for _, pattern := range stringEncPatterns {
		if strings.Contains(strings.ToLower(contentStr), pattern) {
			analysis.StringEncryption = true
			analysis.Indicators = append(analysis.Indicators, fmt.Sprintf("Potential string encryption/obfuscation: %s", pattern))
			break
		}
	}

	if strings.Contains(contentStr, "UPX") {
		analysis.NativeObfuscation = true
		analysis.Indicators = append(analysis.Indicators, "UPX packer detected in native libraries")
	}

	return analysis
}

// detectDeepLinks extracts and analyzes deep link configuration
func (a *Analyzer) detectDeepLinks(decompDir string) *models.DeepLinkAnalysis {
	manifestPath := filepath.Join(decompDir, "AndroidManifest.xml")
	content, err := os.ReadFile(manifestPath)
	if err != nil {

		manifestPath = filepath.Join(decompDir, "resources", "AndroidManifest.xml")
		content, err = os.ReadFile(manifestPath)
		if err != nil {
			return nil
		}
	}

	analysis := &models.DeepLinkAnalysis{}
	contentStr := string(content)

	schemeRegex := regexp.MustCompile(`android:scheme="([^"]+)"`)
	hostRegex := regexp.MustCompile(`android:host="([^"]+)"`)
	pathRegex := regexp.MustCompile(`android:path(?:Pattern|Prefix)?="([^"]+)"`)

	schemes := schemeRegex.FindAllStringSubmatch(contentStr, -1)
	hosts := hostRegex.FindAllStringSubmatch(contentStr, -1)
	paths := pathRegex.FindAllStringSubmatch(contentStr, -1)

	for _, match := range schemes {
		if len(match) > 1 && match[1] != "http" && match[1] != "https" {
			analysis.Schemes = append(analysis.Schemes, match[1])
		}
	}

	for _, match := range hosts {
		if len(match) > 1 {
			analysis.Hosts = append(analysis.Hosts, match[1])
		}
	}

	for _, match := range paths {
		if len(match) > 1 {
			analysis.Paths = append(analysis.Paths, match[1])
		}
	}

	if len(analysis.Schemes) > 0 && len(analysis.Hosts) > 0 {
		for i, scheme := range analysis.Schemes {
			if i >= 3 {
				break
			}
			for j, host := range analysis.Hosts {
				if j >= 2 {
					break
				}
				if len(analysis.Paths) > 0 {
					analysis.ExampleLinks = append(analysis.ExampleLinks,
						fmt.Sprintf("%s://%s%s", scheme, host, analysis.Paths[0]))
				} else {
					analysis.ExampleLinks = append(analysis.ExampleLinks,
						fmt.Sprintf("%s://%s", scheme, host))
				}
			}
		}
	}

	if strings.Contains(contentStr, "autoVerify=\"true\"") {
		analysis.AppLinksVerified = true
		analysis.SecurityNotes = append(analysis.SecurityNotes, "App Links auto-verification enabled")
	}

	if len(analysis.Schemes) == 0 && len(analysis.Hosts) == 0 {
		return nil
	}

	return analysis
}

// detectThirdPartySDKs provides detailed SDK analysis
func (a *Analyzer) detectThirdPartySDKs(packages []models.Package, contentStr string) *models.SDKAnalysis {
	analysis := &models.SDKAnalysis{
		Categories: make(map[string][]models.SDKInfo),
	}

	sdkDatabase := map[string]models.SDKInfo{

		"firebase_analytics": {Name: "Firebase Analytics", Category: "Analytics", Vendor: "Google", PrivacyImpact: "High", DataCollected: []string{"Device info", "Usage patterns", "Crash data"}},
		"google_analytics":   {Name: "Google Analytics", Category: "Analytics", Vendor: "Google", PrivacyImpact: "High", DataCollected: []string{"User behavior", "Demographics", "Events"}},
		"mixpanel":           {Name: "Mixpanel", Category: "Analytics", Vendor: "Mixpanel", PrivacyImpact: "High", DataCollected: []string{"User events", "User properties", "Behavioral data"}},
		"amplitude":          {Name: "Amplitude", Category: "Analytics", Vendor: "Amplitude", PrivacyImpact: "High", DataCollected: []string{"Event tracking", "User segmentation"}},

		"google_mobile_ads":         {Name: "Google Mobile Ads (AdMob)", Category: "Advertising", Vendor: "Google", PrivacyImpact: "High", DataCollected: []string{"Advertising ID", "Location", "Device info"}},
		"facebook_audience_network": {Name: "Facebook Audience Network", Category: "Advertising", Vendor: "Meta", PrivacyImpact: "High", DataCollected: []string{"User profile", "Device ID", "Location"}},
		"unity_ads":                 {Name: "Unity Ads", Category: "Advertising", Vendor: "Unity", PrivacyImpact: "Medium", DataCollected: []string{"Device info", "Ad interactions"}},

		"sentry":               {Name: "Sentry", Category: "Crash Reporting", Vendor: "Sentry", PrivacyImpact: "Medium", DataCollected: []string{"Crash logs", "Stack traces", "Device state"}},
		"firebase_crashlytics": {Name: "Firebase Crashlytics", Category: "Crash Reporting", Vendor: "Google", PrivacyImpact: "Medium", DataCollected: []string{"Crash data", "Device info"}},
		"bugsnag":              {Name: "Bugsnag", Category: "Crash Reporting", Vendor: "Bugsnag", PrivacyImpact: "Medium", DataCollected: []string{"Error logs", "User context"}},

		"firebase_auth":         {Name: "Firebase Authentication", Category: "Authentication", Vendor: "Google", PrivacyImpact: "High", DataCollected: []string{"Email", "Phone", "Auth tokens"}},
		"google_sign_in":        {Name: "Google Sign-In", Category: "Authentication", Vendor: "Google", PrivacyImpact: "High", DataCollected: []string{"Google profile", "Email"}},
		"flutter_facebook_auth": {Name: "Facebook Login", Category: "Authentication", Vendor: "Meta", PrivacyImpact: "High", DataCollected: []string{"Facebook profile", "Email", "Friends list"}},

		"stripe":   {Name: "Stripe", Category: "Payment", Vendor: "Stripe", PrivacyImpact: "High", DataCollected: []string{"Payment info", "Billing address", "Transaction history"}, RequiresCompliance: []string{"PCI-DSS"}},
		"razorpay": {Name: "Razorpay", Category: "Payment", Vendor: "Razorpay", PrivacyImpact: "High", DataCollected: []string{"Payment details", "Contact info"}},
		"paypal":   {Name: "PayPal", Category: "Payment", Vendor: "PayPal", PrivacyImpact: "High", DataCollected: []string{"Payment info", "Transaction data"}},

		"share_plus":           {Name: "Share Plus", Category: "Social", Vendor: "Community", PrivacyImpact: "Low", DataCollected: []string{"Shared content"}},
		"flutter_facebook_sdk": {Name: "Facebook SDK", Category: "Social", Vendor: "Meta", PrivacyImpact: "High", DataCollected: []string{"User interactions", "Device info"}},

		"geolocator":          {Name: "Geolocator", Category: "Location", Vendor: "Community", PrivacyImpact: "High", DataCollected: []string{"GPS coordinates", "Location history"}},
		"google_maps_flutter": {Name: "Google Maps", Category: "Maps", Vendor: "Google", PrivacyImpact: "High", DataCollected: []string{"Location", "Search queries", "Navigation history"}},

		"sqflite":         {Name: "SQFlite", Category: "Storage", Vendor: "Community", PrivacyImpact: "Low", DataCollected: []string{"Local data only"}},
		"hive":            {Name: "Hive", Category: "Storage", Vendor: "Community", PrivacyImpact: "Low", DataCollected: []string{"Local data only"}},
		"cloud_firestore": {Name: "Cloud Firestore", Category: "Database", Vendor: "Google", PrivacyImpact: "High", DataCollected: []string{"User data", "Database queries"}},

		"firebase_messaging": {Name: "Firebase Cloud Messaging", Category: "Push Notifications", Vendor: "Google", PrivacyImpact: "Medium", DataCollected: []string{"Device tokens", "Message data"}},
		"onesignal":          {Name: "OneSignal", Category: "Push Notifications", Vendor: "OneSignal", PrivacyImpact: "Medium", DataCollected: []string{"Device info", "Notification preferences"}},
	}

	for _, pkg := range packages {
		pkgLower := strings.ToLower(pkg.Name)

		for sdkKey, sdkInfo := range sdkDatabase {
			if strings.Contains(pkgLower, sdkKey) {
				sdkInfo.Detected = true
				analysis.Categories[sdkInfo.Category] = append(analysis.Categories[sdkInfo.Category], sdkInfo)
				analysis.TotalSDKs++

				if sdkInfo.PrivacyImpact == "High" {
					analysis.HighPrivacyImpactCount++
				}
			}
		}
	}

	if analysis.TotalSDKs > 0 {
		analysis.PrivacyScore = analysis.HighPrivacyImpactCount * 20
		if analysis.PrivacyScore > 100 {
			analysis.PrivacyScore = 100
		}
	}

	if analysis.TotalSDKs == 0 {
		return nil
	}

	return analysis
}
