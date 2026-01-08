package analyzer

import (
	"path/filepath"
	"strings"

	models "github.com/flutterguard/flutterguard-cli/models"
)

// CDNUIDetector detects CDN usage and UI libraries
type CDNUIDetector struct{}

func NewCDNUIDetector() *CDNUIDetector {
	return &CDNUIDetector{}
}

// DetectCDNs detects CDN usage from domains and content
func (cud *CDNUIDetector) DetectCDNs(content string, domains []string, urlCollection models.URLCollection) []models.CDNInfo {

	urls := map[string][]string{
		"http":    urlCollection.HTTP,
		"https":   urlCollection.HTTPS,
		"ftp":     urlCollection.FTP,
		"ws":      urlCollection.WS,
		"wss":     urlCollection.WSS,
		"file":    urlCollection.File,
		"content": urlCollection.Content,
		"other":   urlCollection.Other,
	}

	var cdns []models.CDNInfo
	contentLower := strings.ToLower(content)

	if cdn := cud.detectCloudflare(contentLower, domains, urls); cdn != nil {
		cdns = append(cdns, *cdn)
	}

	if cdn := cud.detectAkamai(contentLower, domains, urls); cdn != nil {
		cdns = append(cdns, *cdn)
	}

	if cdn := cud.detectFastly(contentLower, domains, urls); cdn != nil {
		cdns = append(cdns, *cdn)
	}

	if cdn := cud.detectCloudFront(contentLower, domains, urls); cdn != nil {
		cdns = append(cdns, *cdn)
	}

	if cdn := cud.detectGoogleCDN(contentLower, domains, urls); cdn != nil {
		cdns = append(cdns, *cdn)
	}

	if cdn := cud.detectAzureCDN(contentLower, domains, urls); cdn != nil {
		cdns = append(cdns, *cdn)
	}

	if cdn := cud.detectStackPath(contentLower, domains, urls); cdn != nil {
		cdns = append(cdns, *cdn)
	}

	if cdn := cud.detectKeyCDN(contentLower, domains, urls); cdn != nil {
		cdns = append(cdns, *cdn)
	}

	if cdn := cud.detectCDN77(contentLower, domains, urls); cdn != nil {
		cdns = append(cdns, *cdn)
	}

	if cdn := cud.detectBunnyCDN(contentLower, domains, urls); cdn != nil {
		cdns = append(cdns, *cdn)
	}

	if cdn := cud.detectLimelight(contentLower, domains, urls); cdn != nil {
		cdns = append(cdns, *cdn)
	}

	if cdn := cud.detectCloudflareMedia(contentLower, domains, urls); cdn != nil {
		cdns = append(cdns, *cdn)
	}

	if cdn := cud.detectImgix(contentLower, domains, urls); cdn != nil {
		cdns = append(cdns, *cdn)
	}

	if cdn := cud.detectjsDelivr(contentLower, domains, urls); cdn != nil {
		cdns = append(cdns, *cdn)
	}

	return cdns
}

func (cud *CDNUIDetector) detectCloudflare(content string, domains []string, urls map[string][]string) *models.CDNInfo {
	indicators := []string{"cloudflare", "cf-ray", "cloudflaressl.com"}
	detectedDomains := filterDomainsByPatterns(domains, indicators)

	if len(detectedDomains) > 0 || strings.Contains(content, "cloudflare") {
		return &models.CDNInfo{
			Name:    "Cloudflare",
			Domains: detectedDomains,
		}
	}
	return nil
}

func (cud *CDNUIDetector) detectAkamai(content string, domains []string, urls map[string][]string) *models.CDNInfo {
	indicators := []string{"akamai", "akamaihd.net", "akamaitechnologies"}
	detectedDomains := filterDomainsByPatterns(domains, indicators)

	if len(detectedDomains) > 0 || strings.Contains(content, "akamai") {
		return &models.CDNInfo{
			Name:    "Akamai",
			Domains: detectedDomains,
		}
	}
	return nil
}

func (cud *CDNUIDetector) detectFastly(content string, domains []string, urls map[string][]string) *models.CDNInfo {
	indicators := []string{"fastly", "fastly.net"}
	detectedDomains := filterDomainsByPatterns(domains, indicators)

	if len(detectedDomains) > 0 || strings.Contains(content, "fastly") {
		return &models.CDNInfo{
			Name:    "Fastly",
			Domains: detectedDomains,
		}
	}
	return nil
}

func (cud *CDNUIDetector) detectCloudFront(content string, domains []string, urls map[string][]string) *models.CDNInfo {
	indicators := []string{"cloudfront.net", "cloudfront"}
	detectedDomains := filterDomainsByPatterns(domains, indicators)

	if len(detectedDomains) > 0 || strings.Contains(content, "cloudfront") {
		return &models.CDNInfo{
			Name:    "Amazon CloudFront",
			Domains: detectedDomains,
		}
	}
	return nil
}

func (cud *CDNUIDetector) detectGoogleCDN(content string, domains []string, urls map[string][]string) *models.CDNInfo {
	indicators := []string{"gstatic.com", "googleusercontent.com"}
	detectedDomains := filterDomainsByPatterns(domains, indicators)

	if len(detectedDomains) > 0 {
		return &models.CDNInfo{
			Name:    "Google Cloud CDN",
			Domains: detectedDomains,
		}
	}
	return nil
}

func (cud *CDNUIDetector) detectAzureCDN(content string, domains []string, urls map[string][]string) *models.CDNInfo {
	indicators := []string{"azureedge.net", "azure-cdn"}
	detectedDomains := filterDomainsByPatterns(domains, indicators)

	if len(detectedDomains) > 0 || strings.Contains(content, "azureedge") {
		return &models.CDNInfo{
			Name:    "Microsoft Azure CDN",
			Domains: detectedDomains,
		}
	}
	return nil
}

func (cud *CDNUIDetector) detectStackPath(content string, domains []string, urls map[string][]string) *models.CDNInfo {
	indicators := []string{"stackpath", "stackpathcdn.com"}
	detectedDomains := filterDomainsByPatterns(domains, indicators)

	if len(detectedDomains) > 0 || strings.Contains(content, "stackpath") {
		return &models.CDNInfo{
			Name:    "StackPath",
			Domains: detectedDomains,
		}
	}
	return nil
}

func (cud *CDNUIDetector) detectKeyCDN(content string, domains []string, urls map[string][]string) *models.CDNInfo {
	indicators := []string{"keycdn", "kxcdn.com"}
	detectedDomains := filterDomainsByPatterns(domains, indicators)

	if len(detectedDomains) > 0 || strings.Contains(content, "keycdn") {
		return &models.CDNInfo{
			Name:    "KeyCDN",
			Domains: detectedDomains,
		}
	}
	return nil
}

func (cud *CDNUIDetector) detectCDN77(content string, domains []string, urls map[string][]string) *models.CDNInfo {
	indicators := []string{"cdn77", "cdn77.org"}
	detectedDomains := filterDomainsByPatterns(domains, indicators)

	if len(detectedDomains) > 0 || strings.Contains(content, "cdn77") {
		return &models.CDNInfo{
			Name:    "CDN77",
			Domains: detectedDomains,
		}
	}
	return nil
}

func (cud *CDNUIDetector) detectBunnyCDN(content string, domains []string, urls map[string][]string) *models.CDNInfo {
	indicators := []string{"bunny.net", "bunnycdn"}
	detectedDomains := filterDomainsByPatterns(domains, indicators)

	if len(detectedDomains) > 0 || strings.Contains(content, "bunnycdn") {
		return &models.CDNInfo{
			Name:    "BunnyCDN",
			Domains: detectedDomains,
		}
	}
	return nil
}

func (cud *CDNUIDetector) detectLimelight(content string, domains []string, urls map[string][]string) *models.CDNInfo {
	indicators := []string{"limelight", "llnwd.net"}
	detectedDomains := filterDomainsByPatterns(domains, indicators)

	if len(detectedDomains) > 0 || strings.Contains(content, "limelight") {
		return &models.CDNInfo{
			Name:    "Limelight Networks",
			Domains: detectedDomains,
		}
	}
	return nil
}

func (cud *CDNUIDetector) detectCloudflareMedia(content string, domains []string, urls map[string][]string) *models.CDNInfo {
	indicators := []string{"cloudflarestream.com", "imagedelivery.net"}
	detectedDomains := filterDomainsByPatterns(domains, indicators)

	if len(detectedDomains) > 0 {
		return &models.CDNInfo{
			Name:    "Cloudflare Images/Stream",
			Domains: detectedDomains,
		}
	}
	return nil
}

func (cud *CDNUIDetector) detectImgix(content string, domains []string, urls map[string][]string) *models.CDNInfo {
	indicators := []string{"imgix.net", "imgix.com"}
	detectedDomains := filterDomainsByPatterns(domains, indicators)

	if len(detectedDomains) > 0 || strings.Contains(content, "imgix") {
		return &models.CDNInfo{
			Name:    "imgix",
			Domains: detectedDomains,
		}
	}
	return nil
}

func (cud *CDNUIDetector) detectjsDelivr(content string, domains []string, urls map[string][]string) *models.CDNInfo {
	indicators := []string{"jsdelivr.net", "jsdelivr"}
	detectedDomains := filterDomainsByPatterns(domains, indicators)

	if len(detectedDomains) > 0 || strings.Contains(content, "jsdelivr") {
		return &models.CDNInfo{
			Name:    "jsDelivr",
			Domains: detectedDomains,
		}
	}
	return nil
}

// DetectUILibraries detects UI libraries and animation frameworks
func (cud *CDNUIDetector) DetectUILibraries(content string, visualAssets []models.FileInfo, packages []models.Package) []models.UILibrary {
	var libraries []models.UILibrary
	contentLower := strings.ToLower(content)

	if lib := cud.detectLottie(contentLower, visualAssets, packages); lib != nil {
		libraries = append(libraries, *lib)
	}

	if lib := cud.detectRive(contentLower, visualAssets, packages); lib != nil {
		libraries = append(libraries, *lib)
	}

	if lib := cud.detectFlare(contentLower, visualAssets, packages); lib != nil {
		libraries = append(libraries, *lib)
	}

	if lib := cud.detectSyncfusion(contentLower, packages); lib != nil {
		libraries = append(libraries, *lib)
	}

	if lib := cud.detectCharts(contentLower, packages); lib != nil {
		libraries = append(libraries, *lib)
	}

	if lib := cud.detectAnimations(contentLower, packages); lib != nil {
		libraries = append(libraries, *lib)
	}

	if lib := cud.detectShimmer(contentLower, packages); lib != nil {
		libraries = append(libraries, *lib)
	}

	return libraries
}

func (cud *CDNUIDetector) detectLottie(content string, visualAssets []models.FileInfo, packages []models.Package) *models.UILibrary {
	lottieFiles := []string{}
	for _, asset := range visualAssets {
		if strings.HasSuffix(strings.ToLower(asset.Name), ".json") {

			pathLower := strings.ToLower(asset.Path)
			if strings.Contains(pathLower, "lottie") || strings.Contains(pathLower, "animation") {
				lottieFiles = append(lottieFiles, asset.Name)
			}
		}
	}

	var version string
	for _, pkg := range packages {
		if pkg.Name == "lottie" {
			version = pkg.Version
			break
		}
	}

	if len(lottieFiles) > 0 || strings.Contains(content, "lottie") || version != "" {
		return &models.UILibrary{
			Name:           "Lottie",
			Type:           "animation",
			Files:          lottieFiles,
			PackageVersion: version,
		}
	}
	return nil
}

func (cud *CDNUIDetector) detectRive(content string, visualAssets []models.FileInfo, packages []models.Package) *models.UILibrary {
	riveFiles := []string{}
	for _, asset := range visualAssets {
		ext := strings.ToLower(filepath.Ext(asset.Name))
		if ext == ".riv" || ext == ".flr2" {
			riveFiles = append(riveFiles, asset.Name)
		}
	}

	var version string
	for _, pkg := range packages {
		if pkg.Name == "rive" {
			version = pkg.Version
			break
		}
	}

	if len(riveFiles) > 0 || strings.Contains(content, "rive") || version != "" {
		return &models.UILibrary{
			Name:           "Rive",
			Type:           "animation",
			Files:          riveFiles,
			PackageVersion: version,
		}
	}
	return nil
}

func (cud *CDNUIDetector) detectFlare(content string, visualAssets []models.FileInfo, packages []models.Package) *models.UILibrary {
	flareFiles := []string{}
	for _, asset := range visualAssets {
		if strings.HasSuffix(strings.ToLower(asset.Name), ".flr") {
			flareFiles = append(flareFiles, asset.Name)
		}
	}

	var version string
	for _, pkg := range packages {
		if pkg.Name == "flare_flutter" {
			version = pkg.Version
			break
		}
	}

	if len(flareFiles) > 0 || strings.Contains(content, "flare") || version != "" {
		return &models.UILibrary{
			Name:           "Flare",
			Type:           "animation",
			Files:          flareFiles,
			PackageVersion: version,
		}
	}
	return nil
}

func (cud *CDNUIDetector) detectSyncfusion(content string, packages []models.Package) *models.UILibrary {
	var version string
	for _, pkg := range packages {
		if strings.HasPrefix(pkg.Name, "syncfusion_flutter") {
			version = pkg.Version
			break
		}
	}

	if strings.Contains(content, "syncfusion") || version != "" {
		return &models.UILibrary{
			Name:           "Syncfusion",
			Type:           "widget",
			PackageVersion: version,
		}
	}
	return nil
}

func (cud *CDNUIDetector) detectCharts(content string, packages []models.Package) *models.UILibrary {
	var version string
	chartPackages := []string{"fl_chart", "charts_flutter", "syncfusion_flutter_charts"}

	for _, pkg := range packages {
		for _, chartPkg := range chartPackages {
			if pkg.Name == chartPkg {
				version = pkg.Version
				break
			}
		}
		if version != "" {
			break
		}
	}

	if strings.Contains(content, "chart") || version != "" {
		return &models.UILibrary{
			Name:           "Charts Library",
			Type:           "chart",
			PackageVersion: version,
		}
	}
	return nil
}

func (cud *CDNUIDetector) detectAnimations(content string, packages []models.Package) *models.UILibrary {
	var version string
	for _, pkg := range packages {
		if pkg.Name == "animations" {
			version = pkg.Version
			break
		}
	}

	if version != "" {
		return &models.UILibrary{
			Name:           "Flutter Animations",
			Type:           "animation",
			PackageVersion: version,
		}
	}
	return nil
}

func (cud *CDNUIDetector) detectShimmer(content string, packages []models.Package) *models.UILibrary {
	var version string
	for _, pkg := range packages {
		if pkg.Name == "shimmer" {
			version = pkg.Version
			break
		}
	}

	if strings.Contains(content, "shimmer") || version != "" {
		return &models.UILibrary{
			Name:           "Shimmer",
			Type:           "effect",
			PackageVersion: version,
		}
	}
	return nil
}

func filterDomainsByPatterns(domains []string, patterns []string) []string {
	var matched []string
	for _, domain := range domains {
		domainLower := strings.ToLower(domain)
		for _, pattern := range patterns {
			if strings.Contains(domainLower, strings.ToLower(pattern)) {
				matched = append(matched, domain)
				break
			}
		}
	}
	return uniqueList(matched)
}

func uniqueList(slice []string) []string {
	keys := make(map[string]bool)
	var unique []string
	for _, entry := range slice {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			unique = append(unique, entry)
		}
	}
	return unique
}
