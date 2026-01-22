package analyzer

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	models "github.com/flutterguard/flutterguard-cli/models"
)

type Analyzer struct {
	cfg                     *Config
	decompiler              *Decompiler
	extractor               *PatternExtractor
	aapt2                   *AAPT2Extractor
	certAnalyzer            *CertificateAnalyzer
	advancedServiceDetector *AdvancedServiceDetector
	envExtractor            *EnvExtractor
	cdnUIDetector           *CDNUIDetector
	pubDevClient            *PubDevClient
	emailValidator          *EmailValidator
	domainValidator         *DomainValidator
	urlValidator            *URLValidator
	endpointValidator       *EndpointValidator
}

func NewAnalyzer(cfg *Config) *Analyzer {
	validateDNS := !cfg.DisableNetworkChecks
	return &Analyzer{
		cfg:                     cfg,
		decompiler:              NewDecompiler(cfg),
		extractor:               NewPatternExtractor(validateDNS),
		aapt2:                   NewAAPT2Extractor(cfg),
		certAnalyzer:            NewCertificateAnalyzer(),
		advancedServiceDetector: NewAdvancedServiceDetector(),
		envExtractor:            NewEnvExtractor(),
		cdnUIDetector:           NewCDNUIDetector(),
		pubDevClient:            NewPubDevClient(),
		emailValidator:          NewEmailValidator(validateDNS),
		domainValidator:         NewDomainValidator(validateDNS),
		urlValidator:            NewURLValidator(validateDNS),
		endpointValidator:       NewEndpointValidator(),
	}
}

// AnalyzeAPK performs full analysis on an APK file
func (a *Analyzer) AnalyzeAPK(ctx context.Context, apkPath string, progress ProgressReporter) (*models.Results, error) {
	results := &models.Results{
		URLs: models.URLCollection{},
	}

	decompDir := apkPath + "-decompiled"
	var stageErrors []string

	emitProgress(progress, 10, "init", "starting analysis")

	if a.aapt2.IsAvailable() {
		emitProgress(progress, 12, "aapt2", "extract metadata")
		aapt2Data, err := a.aapt2.ExtractMetadata(ctx, apkPath)
		if err == nil {
			results.AAPT2Metadata = aapt2Data
		} else {
			msg := fmt.Sprintf("AAPT2 extraction failed: %v", err)
			stageErrors = append(stageErrors, msg)
			if a.cfg.Verbose {
				fmt.Fprintf(os.Stderr, "Warning: %s\n", msg)
			}
		}
	}

	emitProgress(progress, 15, "decompile", "select strategy")

	decompResult, err := a.decompiler.DecompileWithStrategies(ctx, apkPath, decompDir)
	if err != nil {
		msg := fmt.Sprintf("Decompilation failed: %v", err)
		stageErrors = append(stageErrors, msg)
		if a.cfg.Verbose {
			fmt.Fprintf(os.Stderr, "Warning: %s\n", msg)
		}
		// Can't continue without decompilation, return partial results
		results.Errors = stageErrors
		return results, nil
	}

	emitProgress(progress, 20, "decompile", "completed")

	libappPath, libappErr := a.decompiler.FindLibAppSO(decompDir)
	isFlutterApp := libappErr == nil && libappPath != ""

	results.DecompilerUsed = decompResult.Strategy
	results.DecompilationAttempts = decompResult.Attempts

	var contentStr string
	var libappContent []byte

	if isFlutterApp {
		var err error
		libappContent, err = os.ReadFile(libappPath)
		if err != nil {
			msg := fmt.Sprintf("Reading libapp.so failed: %v", err)
			stageErrors = append(stageErrors, msg)
			if a.cfg.Verbose {
				fmt.Fprintf(os.Stderr, "Warning: %s\n", msg)
			}
		} else {
			contentStr = string(libappContent)
		}
	} else {
		var err error
		contentStr, err = a.decompiler.ReadDecompiledSources(decompDir)
		if err != nil {
			msg := fmt.Sprintf("Reading decompiled sources failed: %v", err)
			stageErrors = append(stageErrors, msg)
			if a.cfg.Verbose {
				fmt.Fprintf(os.Stderr, "Warning: %s\n", msg)
			}
		}
	}

	// If we have neither contentStr nor libappContent, can't continue
	if contentStr == "" && len(libappContent) == 0 {
		results.Errors = stageErrors
		return results, nil
	}

	emitProgress(progress, 30, "extract", "scan strings")
	defer func() { results.Errors = stageErrors }()
	// Extraction stages
	var urls map[string][]string // <-- move declaration here for wider scope
	if contentStr != "" {
		// Emails
		defer func() { recover() }()
		rawEmails := a.extractor.ExtractEmails(contentStr)
		for _, email := range rawEmails {
			if a.emailValidator.ValidateEmail(email) {
				results.Emails = append(results.Emails, email)
			}
		}

		emitProgress(progress, 35, "extract", "urls/emails")
		// URLs
		func() {
			defer func() {
				if r := recover(); r != nil {
					stageErrors = append(stageErrors, "URL extraction failed")
				}
			}()
			rawURLs := a.extractor.ExtractURLs(contentStr)
			urls = make(map[string][]string)
			for scheme, urlList := range rawURLs {
				validURLs := []string{}
				for _, rawURL := range urlList {
					if valid, _ := a.urlValidator.ValidateURL(rawURL); valid {
						validURLs = append(validURLs, rawURL)
					}
				}
				urls[scheme] = validURLs
			}
			results.URLs.HTTP = urls["http"]
			results.URLs.HTTPS = urls["https"]
			results.URLs.FTP = urls["ftp"]
			results.URLs.WS = urls["ws"]
			results.URLs.WSS = urls["wss"]
			results.URLs.File = urls["file"]
			results.URLs.Content = urls["content"]
			results.URLs.Other = urls["other"]
		}()

		emitProgress(progress, 40, "extract", "domains/endpoints")
		// Domains
		func() {
			defer func() {
				if r := recover(); r != nil {
					stageErrors = append(stageErrors, "Domain extraction failed")
				}
			}()
			rawDomains := a.extractor.ExtractDomains(contentStr)
			for _, domain := range rawDomains {
				if valid, _ := a.domainValidator.ValidateDomain(domain); valid {
					results.Domains = append(results.Domains, domain)
				}
			}
		}()
		// IPs
		func() {
			defer func() {
				if r := recover(); r != nil {
					stageErrors = append(stageErrors, "IP extraction failed")
				}
			}()
			results.IPAddresses = a.extractor.ExtractIPAddresses(contentStr)
		}()
		// API Endpoints
		func() {
			defer func() {
				if r := recover(); r != nil {
					stageErrors = append(stageErrors, "API endpoint extraction failed")
				}
			}()
			if urls == nil {
				urls = make(map[string][]string)
			}
			rawAPIEndpoints := a.extractor.ExtractEndpointsWithDomain(contentStr, urls)
			for _, endpoint := range rawAPIEndpoints {
				if a.endpointValidator.ValidateFullEndpointURL(endpoint.URL) {
					results.APIEndpoints = append(results.APIEndpoints, endpoint)
				}
			}
		}()
		// Endpoints without domain
		func() {
			defer func() {
				if r := recover(); r != nil {
					stageErrors = append(stageErrors, "EndpointsNoDomain extraction failed")
				}
			}()
			results.EndpointsNoDomain = a.extractor.ExtractEndpointsNoDomain(contentStr)
		}()
		// Potential endpoints
		results.PotentialEndpointsFull = uniqueStrings(append(results.URLs.HTTP, results.URLs.HTTPS...))
		results.PotentialEndpointsRoutes = uniqueStrings(results.EndpointsNoDomain)
		// HTTP requests
		func() {
			defer func() {
				if r := recover(); r != nil {
					stageErrors = append(stageErrors, "HTTP request extraction failed")
				}
			}()
			results.HTTPRequests = a.extractor.ExtractHTTPRequests(contentStr)
			results.RequestHeaders = a.extractor.ExtractRequestHeaders(contentStr)
		}()
		// Method channels
		func() {
			defer func() {
				if r := recover(); r != nil {
					stageErrors = append(stageErrors, "Method channel extraction failed")
				}
			}()
			results.MethodChannels = a.extractor.ExtractMethodChannels(contentStr)
		}()
		emitProgress(progress, 45, "extract", "contacts/imports")
		// Phone numbers
		func() {
			defer func() {
				if r := recover(); r != nil {
					stageErrors = append(stageErrors, "Phone number extraction failed")
				}
			}()
			results.PhoneNumbers = a.extractor.ExtractPhoneNumbers(contentStr)
		}()
		// Imports
		func() {
			defer func() {
				if r := recover(); r != nil {
					stageErrors = append(stageErrors, "Imports extraction failed")
				}
			}()
			results.Imports = a.extractor.ExtractImports(contentStr)
		}()
		emitProgress(progress, 50, "packages", "detect packages")
		// Packages
		var packageNames []string
		func() {
			defer func() {
				if r := recover(); r != nil {
					stageErrors = append(stageErrors, "Package extraction failed")
				}
			}()
			results.AppPackageName = a.extractor.ExtractAppPackageName(contentStr)
			packageNames = a.extractor.ExtractPackages(contentStr, results.AppPackageName)
		}()
		// Enrich packages with pub.dev data only when network checks enabled
		var enrichedData map[string]*PubDevPackageScore
		if !a.cfg.DisableNetworkChecks {
			enrichCtx, enrichCancel := context.WithTimeout(ctx, 35*time.Second)
			defer enrichCancel()
			enrichedData = a.pubDevClient.EnrichPackages(enrichCtx, packageNames)
		} else {
			enrichedData = make(map[string]*PubDevPackageScore)
		}
		for _, pkg := range packageNames {
			packageInfo := models.Package{
				Name: pkg,
				URL:  fmt.Sprintf("https://pub.dev/packages/%s", pkg),
			}
			if enrichment, ok := enrichedData[pkg]; ok && enrichment != nil {
				packageInfo.GrantedPoints = enrichment.GrantedPoints
				packageInfo.MaxPoints = enrichment.MaxPoints
				packageInfo.LikeCount = enrichment.LikeCount
				packageInfo.DownloadCount30Days = enrichment.DownloadCount30Days
				packageInfo.Tags = enrichment.Tags
			}
			results.Packages = append(results.Packages, packageInfo)
		}
		func() {
			defer func() {
				if r := recover(); r != nil {
					stageErrors = append(stageErrors, "AppPackagePaths extraction failed")
				}
			}()
			results.AppPackagePaths = a.extractor.ExtractAppPackagePaths(contentStr, results.AppPackageName)
		}()
	}

	emitProgress(progress, 60, "manifest", "permissions & debug flags")
	// Manifest and debug info
	func() {
		defer func() {
			if r := recover(); r != nil {
				stageErrors = append(stageErrors, "Manifest/permissions extraction failed")
			}
		}()
		results.Permissions = a.decompiler.ExtractManifestPermissions(decompDir)
		if len(results.Permissions) == 0 && results.AAPT2Metadata != nil {
			var permStrings []string
			permStrings = append(permStrings, results.AAPT2Metadata.Permissions...)
			if results.AAPT2Metadata.Badging != nil {
				permStrings = append(permStrings, results.AAPT2Metadata.Badging.UsesPermissions...)
			}
			seen := make(map[string]bool)
			for _, p := range permStrings {
				if p == "" || seen[p] {
					continue
				}
				seen[p] = true
				results.Permissions = append(results.Permissions, models.Permission{
					Name:        p,
					Dangerous:   isDangerousPermission(p),
					Description: getPermissionDescription(p),
				})
			}
		}
		results.DebugInfo = &models.DebugInfo{ManifestDebuggable: a.decompiler.IsDebuggable(decompDir)}
		if results.DebugInfo.ManifestDebuggable {
			results.DebugInfo.Indicators = append(results.DebugInfo.Indicators, "AndroidManifest debuggable=true")
		}
		if fb := a.decompiler.FindFirebaseConfig(decompDir); fb != nil {
			results.Firebase = fb
		}
	}()

	// Services
	var services []models.ServiceUsage
	func() {
		defer func() {
			if r := recover(); r != nil {
				stageErrors = append(stageErrors, "Service detection failed")
			}
		}()
		detectedServices := a.advancedServiceDetector.DetectAllServices(contentStr, results.Domains)
		services = append(services, detectedServices...)
		firebaseDomains := []string{
			"firebaseio.com",
			"firebasestorage.googleapis.com",
			"firebaseapp.com",
			"googleapis.com",
			"gstatic.com",
		}
		if containsAny(results.Domains, firebaseDomains) || results.Firebase != nil {
			fbService := models.ServiceUsage{
				Name:       "Firebase",
				Domains:    filterDomains(results.Domains, firebaseDomains),
				Packages:   filterPackages(results.Packages, []string{"firebase_", "cloud_firestore"}),
				Indicators: []string{"Firebase SDK detected"},
			}
			alreadyDetected := false
			for _, svc := range services {
				if svc.Name == "Firebase" {
					alreadyDetected = true
					break
				}
			}
			if !alreadyDetected {
				services = append(services, fbService)
			}
		}
		if containsAny(results.Domains, []string{"supabase.co"}) || containsAny(results.Imports, []string{"supabase_flutter", "postgrest"}) {
			services = append(services, models.ServiceUsage{
				Name:       "Supabase",
				Domains:    filterDomains(results.Domains, []string{"supabase.co"}),
				Packages:   filterPackages(results.Packages, []string{"supabase_", "postgrest"}),
				Indicators: []string{"Supabase domain or packages present"},
			})
		}
		stripeKeys := a.extractor.DetectServiceKeys(contentStr)
		if len(stripeKeys) > 0 || containsAny(results.Domains, []string{"stripe.com", "api.stripe.com"}) {
			services = append(services, models.ServiceUsage{
				Name:       "Stripe",
				Domains:    filterDomains(results.Domains, []string{"stripe.com", "api.stripe.com"}),
				Packages:   filterPackages(results.Packages, []string{"stripe_", "flutter_stripe"}),
				Keys:       maskKeys(stripeKeys),
				Indicators: []string{"Stripe publishable key or domain detected"},
			})
		}
		results.Services = services
	}()

	// AppInfo
	func() {
		defer func() {
			if r := recover(); r != nil {
				stageErrors = append(stageErrors, "App metadata extraction failed")
			}
		}()
		results.AppInfo = a.decompiler.ExtractAppMetadata(decompDir, apkPath, contentStr)
	}()

	emitProgress(progress, 65, "services", "service detection")

	// SQL, keys, hints, CDNs
	func() {
		defer func() {
			if r := recover(); r != nil {
				stageErrors = append(stageErrors, "SQL/keys/hints/CDN extraction failed")
			}
		}()
		results.SQLCommands = a.extractor.ExtractSQLCommands(contentStr)
		results.SQLiteDatabases = a.extractor.ExtractSQLiteDatabases(contentStr)
		results.HardcodedKeys = uniqueStrings(a.detectHardcodedKeys(contentStr))
		results.InstallSourceHints = uniqueStrings(a.detectInstallSources(contentStr))
		results.EnvironmentHints = uniqueStrings(a.detectEnvironmentHints(contentStr))
		results.CDNs = a.cdnUIDetector.DetectCDNs(contentStr, results.Domains, results.URLs)
		// Use the urls map from earlier extraction for detectCDNs
		var cdnUrls map[string][]string
		if urls != nil {
			cdnUrls = urls
		} else {
			cdnUrls = map[string][]string{}
		}
		results.CDNUsage = uniqueStrings(a.detectCDNs(contentStr, cdnUrls))
	}()

	emitProgress(progress, 70, "assets", "scan env/config/content")

	// Asset scanning
	func() {
		defer func() {
			if r := recover(); r != nil {
				stageErrors = append(stageErrors, "Asset/env/config/content scan failed")
			}
		}()
		results.EnvData = a.envExtractor.ExtractEnvFiles(decompDir)
		results.EnvFiles = a.scanForFiles(decompDir, []string{".env"}, true)
		emitProgress(progress, 75, "assets", ".env files")
		results.ConfigFiles = a.scanForFiles(decompDir, []string{".json", ".yaml", ".yml", ".xml", ".properties", ".ini"}, true)
		emitProgress(progress, 85, "assets", "config files")
		results.ContentFiles = a.scanForFiles(decompDir, []string{".md", ".txt", ".html", ".htm", ".css", ".js"}, true)
		emitProgress(progress, 90, "assets", "content files")
		results.VisualAssets = a.scanForFiles(decompDir,
			[]string{".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".bmp", ".ico", ".ttf", ".mp3", ".mp4", ".avi", ".wav"},
			true)
		emitProgress(progress, 95, "assets", "visual assets")
		appIcon := a.findAppIcon(results.VisualAssets)
		if appIcon != "" {
			results.AppInfo.AppIconPath = appIcon
		}
		allFiles := append([]models.FileInfo{}, results.VisualAssets...)
		allFiles = append(allFiles, results.ConfigFiles...)
		allFiles = append(allFiles, results.EnvFiles...)
		allFiles = append(allFiles, results.ContentFiles...)
		results.AssetSizes = a.computeAssetSizes(allFiles)
		results.FileTypes = a.analyzeFileTypes(decompDir)
		results.UILibraries = a.cdnUIDetector.DetectUILibraries(contentStr, results.VisualAssets, results.Packages)
		uiInfo := a.extractor.DetectUIComponents(contentStr, results.VisualAssets)
		if libs, ok := uiInfo["ui_libraries"].([]string); ok {
			results.UIComponents = &models.UIComponentInfo{}
			results.UIComponents.Libraries = libs
			if lf, ok := uiInfo["lottie_files"].([]string); ok {
				results.UIComponents.LottieFiles = lf
			}
			if lc, ok := uiInfo["lottie_count"].(int); ok {
				results.UIComponents.LottieCount = lc
			}
		}
		results.SDKBloat = a.analyzeSDAKBloat(results.Packages, results.AppInfo.APKSize)
		decompZipPath, err := a.createDecompZip(decompDir)
		if err == nil && decompZipPath != "" {
			decompInfo, _ := os.Stat(decompZipPath)
			if decompInfo != nil {
				results.DecompiledFolderPath = decompZipPath
				results.ContentFiles = append(results.ContentFiles, models.FileInfo{
					Name: "decompiled_sources.zip",
					Path: decompZipPath,
					Size: decompInfo.Size(),
				})
			}
		}
		results.Fingerprints = &models.BinaryFingerprints{
			APKSHA256:    fileSHA256(apkPath),
			LibappSHA256: sha256String(libappContent),
		}
	}()

	// Certificate analysis
	if a.certAnalyzer.IsAvailable() {
		certInfo, err := a.certAnalyzer.AnalyzeCertificates(ctx, decompDir)
		if err == nil {
			results.CertificateInfo = certInfo
		} else {
			msg := fmt.Sprintf("Certificate analysis failed: %v", err)
			stageErrors = append(stageErrors, msg)
			if a.cfg.Verbose {
				fmt.Fprintf(os.Stderr, "Warning: %s\n", msg)
			}
		}
	}

	// Security and summary
	func() {
		defer func() {
			if r := recover(); r != nil {
				stageErrors = append(stageErrors, "Security/summary analysis failed")
			}
		}()
		results.NetworkSecurity = a.detectNetworkSecurity(decompDir)
		results.DataStorage = a.detectDataStorage(contentStr)
		results.WebViewSecurity = a.detectWebViewSecurity(contentStr)
		results.Obfuscation = a.detectObfuscation(contentStr, decompDir)
		results.DeepLinks = a.detectDeepLinks(decompDir)
		results.SDKAnalysis = a.detectThirdPartySDKs(results.Packages, contentStr)
		results.Summary = a.generateSummary(results)
		emitProgress(progress, 100, "done", "analysis complete")
		results.DecompiledDirPath = decompDir
	}()

	return results, nil
}

func containsAny(list []string, needles []string) bool {
	for _, s := range list {
		for _, n := range needles {
			if strings.Contains(strings.ToLower(s), strings.ToLower(n)) {
				return true
			}
		}
	}
	return false
}

func filterDomains(domains []string, needles []string) []string {
	var out []string
	for _, d := range domains {
		for _, n := range needles {
			if strings.Contains(strings.ToLower(d), strings.ToLower(n)) {
				out = append(out, d)
				break
			}
		}
	}
	return uniqueStringsLocal(out)
}

func filterPackages(pkgs []models.Package, prefixes []string) []string {
	var out []string
	for _, p := range pkgs {
		for _, pref := range prefixes {
			if strings.HasPrefix(strings.ToLower(p.Name), strings.ToLower(pref)) {
				out = append(out, p.Name)
				break
			}
		}
	}
	return uniqueStringsLocal(out)
}

func maskKeys(keys []string) []string {
	var out []string
	for _, k := range keys {
		if len(k) > 10 {
			out = append(out, k[:6]+"***"+k[len(k)-2:])
		} else {
			out = append(out, k)
		}
	}
	return out
}

// analyzeSDAKBloat estimates SDK size impact (heuristic: larger known SDKs)
func (a *Analyzer) analyzeSDAKBloat(packages []models.Package, totalAPKSize int64) []models.SDKImpact {

	knownSizes := map[string]float64{

		"firebase_core":          2.5,
		"firebase_auth":          3.0,
		"cloud_firestore":        4.5,
		"firebase_storage":       2.0,
		"firebase_analytics":     1.8,
		"firebase_messaging":     2.2,
		"firebase_remote_config": 1.5,
		"firebase_crashlytics":   2.0,
		"firebase_performance":   1.2,

		"google_maps_flutter": 5.0,
		"google_mobile_ads":   2.5,
		"google_sign_in":      1.8,
		"google_fonts":        1.0,
		"google_nav_bar":      0.8,

		"facebook_login":            3.5,
		"facebook_audience_network": 2.5,
		"flutter_facebook_login":    2.0,
		"sign_in_with_apple":        1.5,

		"in_app_purchase":          2.0,
		"revenue_cat":              1.5,
		"in_app_purchase_storekit": 1.8,

		"sentry_flutter":  2.0,
		"sentry":          2.0,
		"bugsnag_flutter": 1.5,

		"appsflyer":         1.5,
		"adjust":            1.2,
		"amplitude_flutter": 1.8,
		"mixpanel_flutter":  1.5,

		"video_player":           2.5,
		"camera":                 2.0,
		"image_picker":           1.5,
		"file_picker":            1.2,
		"video_trimmer":          2.0,
		"image_cropper":          1.8,
		"image_compress_flutter": 1.0,

		"onesignal_flutter":           1.5,
		"flutter_local_notifications": 1.0,
		"awesome_notifications":       1.2,

		"syncfusion_flutter":          8.0,
		"syncfusion_flutter_datagrid": 3.0,
		"syncfusion_flutter_charts":   2.5,
		"syncfusion_flutter_calendar": 2.0,
		"syncfusion_flutter_pdf":      3.5,
		"syncfusion_flutter_sliders":  1.5,
		"flutter_lottie":              1.2,
		"lottie":                      1.2,

		"animation_presets":    0.8,
		"animations":           0.8,
		"staggered_animations": 0.6,

		"fl_chart":       1.5,
		"charts_flutter": 2.0,
		"mpflutter":      1.8,
		"graphic":        1.5,

		"sqflite":           1.0,
		"hive":              1.2,
		"moor":              1.5,
		"drift":             1.5,
		"isar":              2.0,
		"realm":             2.5,
		"firebase_database": 2.0,

		"dio":             0.8,
		"http":            0.5,
		"graphql":         1.2,
		"graphql_flutter": 1.2,

		"provider": 0.3,
		"riverpod": 0.4,
		"bloc":     0.5,
		"get":      0.6,
		"mobx":     0.7,

		"device_info_plus":   0.8,
		"package_info_plus":  0.5,
		"permission_handler": 1.2,
		"location":           1.0,
		"geolocator":         1.2,

		"aws_sdk_flutter":   3.0,
		"aws_api_gateway":   2.0,
		"azure_sdk_flutter": 2.5,

		"twilio_flutter":   1.8,
		"sendgrid_flutter": 1.0,
		"stripe_flutter":   2.5,
		"razorpay_flutter": 2.0,
		"paypal_checkout":  2.2,
		"admob_google":     2.5,
		"unity_ads":        2.0,
		"app_lovin":        1.8,
		"branch_flutter":   1.5,
		"slack_flutter":    1.8,
		"telegram":         2.0,
		"web3dart":         3.5,
		"solana":           2.5,
		"near_api":         1.8,
	}

	var impacts []models.SDKImpact
	totalEstimatedMB := 0.0

	for _, pkg := range packages {
		for prefix, sizeMB := range knownSizes {
			if strings.HasPrefix(strings.ToLower(pkg.Name), prefix) {
				sizeBytes := int64(sizeMB * 1024 * 1024)
				impacts = append(impacts, models.SDKImpact{
					Name:      pkg.Name,
					SizeBytes: sizeBytes,
					SizeMB:    sizeMB,
				})
				totalEstimatedMB += sizeMB
				break
			}
		}
	}

	if totalAPKSize > 0 {
		for i := range impacts {
			impacts[i].PercentTotal = (impacts[i].SizeMB * 1024 * 1024 / float64(totalAPKSize)) * 100
		}
	}

	return impacts
}

func uniqueStringsLocal(in []string) []string {
	m := make(map[string]struct{})
	var out []string
	for _, s := range in {
		if _, ok := m[s]; !ok {
			m[s] = struct{}{}
			out = append(out, s)
		}
	}
	return out
}
