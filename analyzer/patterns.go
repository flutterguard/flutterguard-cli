package analyzer

import (
	"regexp"
	"strings"
	models "github.com/flutterguard/flutterguard-cli/models"
)

// PatternExtractor contains regex patterns for data extraction
type PatternExtractor struct {
	emailRegex       *regexp.Regexp
	urlRegex         *regexp.Regexp
	domainRegex      *regexp.Regexp
	phoneRegex       *regexp.Regexp
	ipRegex          *regexp.Regexp
	apiEndpointRegex *regexp.Regexp
	packageRegex     *regexp.Regexp
	sqlCommandRegex  *regexp.Regexp
	sqliteDBRegex    *regexp.Regexp
	importRegex      *regexp.Regexp
	httpMethodRegex  *regexp.Regexp
	headerRegex      *regexp.Regexp
	methodChannelRegex *regexp.Regexp
	stripeKeyRegex     *regexp.Regexp
	lottieRegex        *regexp.Regexp
	syncfusionRegex    *regexp.Regexp
	emailValidator     *EmailValidator
	urlValidator       *URLValidator
	domainValidator    *DomainValidator
	ipValidator        *IPValidator
	phoneValidator     *PhoneValidator
	endpointValidator  *EndpointValidator
	headerValidator    *HTTPHeaderValidator
}

func NewPatternExtractor(validateDNS bool) *PatternExtractor {
	return &PatternExtractor{
		emailRegex:       regexp.MustCompile(`[-0-9a-zA-Z.+_]+@[-0-9a-zA-Z.+_]+\.[a-zA-Z]{2,4}`),
		urlRegex:         regexp.MustCompile(`\b\w+://[-A-Za-z0-9+&@#/%?=~_|!:,.;]*[-A-Za-z0-9+&@#/%=~_|]+`),
		domainRegex:      regexp.MustCompile(`(?i)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]`),
		phoneRegex:       regexp.MustCompile(`\+?[1-9]\d{1,14}(?:[\s.-]?\d{1,13})?`),
		ipRegex:          regexp.MustCompile(`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`),
		apiEndpointRegex: regexp.MustCompile(`/[a-zA-Z0-9_-]+/?[a-zA-Z0-9_-]*`),
		packageRegex:     regexp.MustCompile(`package:([^:/]+)/`),
		sqlCommandRegex:  regexp.MustCompile(`\b(SELECT|INSERT|UPDATE|DELETE|CREATE|DROP|ALTER|TRUNCATE|REPLACE|GRANT|REVOKE|LOCK|UNLOCK|RENAME|COMMENT|CALL|START|COMMIT|ROLLBACK|SAVEPOINT|SET|SHOW|DESCRIBE|EXPLAIN|HELP|USE|ANALYZE|ATTACH|BEGIN|DETACH|END|PRAGMA|VACUUM)\b`),
		sqliteDBRegex:    regexp.MustCompile(`\b[a-zA-Z0-9_-]+\.db\b`),
		importRegex:      regexp.MustCompile(`(?:^|;)\s*import\s+['"]([^'"]+)['"]`),
		httpMethodRegex:  regexp.MustCompile(`\b(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\b`),
		headerRegex:      regexp.MustCompile(`['"]([A-Za-z-]+)['"]\s*:\s*['"]([^'"]+)['"]`),
		methodChannelRegex: regexp.MustCompile(`MethodChannel\(['"]([^'"]+)['"]\)`),
		stripeKeyRegex:     regexp.MustCompile(`pk_(?:live|test)_[0-9a-zA-Z]{20,}`),
		lottieRegex:        regexp.MustCompile(`(?i)lottie|assets/.*\.json`),
		syncfusionRegex:    regexp.MustCompile(`(?i)syncfusion`),
		emailValidator:     NewEmailValidator(validateDNS),
		urlValidator:       NewURLValidator(validateDNS),
		domainValidator:    NewDomainValidator(validateDNS),
		ipValidator:        NewIPValidator(),
		phoneValidator:     NewPhoneValidator(),
		endpointValidator:  NewEndpointValidator(),
		headerValidator:    NewHTTPHeaderValidator(),
	}
}

// ExtractEmails finds all email addresses in the content
func (p *PatternExtractor) ExtractEmails(content string) []string {
	matches := p.emailRegex.FindAllString(content, -1)
	var validated []string
	for _, email := range matches {
		if p.emailValidator.ValidateEmail(email) {
			validated = append(validated, email)
		}
	}
	return uniqueStrings(validated)
}

// ExtractURLs finds all URLs in the content and categorizes them
func (p *PatternExtractor) ExtractURLs(content string) map[string][]string {
	matches := p.urlRegex.FindAllString(content, -1)
	
	urls := map[string][]string{
		"http":    []string{},
		"https":   []string{},
		"ftp":     []string{},
		"ws":      []string{},
		"wss":     []string{},
		"file":    []string{},
		"content": []string{},
		"other":   []string{},
	}

	for _, url := range matches {
		lower := strings.ToLower(url)
		switch {
		case strings.HasPrefix(lower, "http://"):
			urls["http"] = append(urls["http"], url)
		case strings.HasPrefix(lower, "https://"):
			urls["https"] = append(urls["https"], url)
		case strings.HasPrefix(lower, "ftp://"):
			urls["ftp"] = append(urls["ftp"], url)
		case strings.HasPrefix(lower, "ws://"):
			urls["ws"] = append(urls["ws"], url)
		case strings.HasPrefix(lower, "wss://"):
			urls["wss"] = append(urls["wss"], url)
		case strings.HasPrefix(lower, "file://"):
			urls["file"] = append(urls["file"], url)
		case strings.HasPrefix(lower, "content://"):
			urls["content"] = append(urls["content"], url)
		default:
			urls["other"] = append(urls["other"], url)
		}
	}

	// Deduplicate
	for key := range urls {
		urls[key] = uniqueStrings(urls[key])
	}

	return urls
}

// ExtractPhoneNumbers finds valid international phone numbers
func (p *PatternExtractor) ExtractPhoneNumbers(content string) []string {
	matches := p.phoneRegex.FindAllString(content, -1)
	
	var validated []string
	for _, phone := range matches {
		if p.phoneValidator.ValidatePhone(phone) {
			validated = append(validated, phone)
		}
	}
	
	return uniqueStrings(validated)
}

// ExtractAPIEndpoints finds potential API endpoints
func (p *PatternExtractor) ExtractAPIEndpoints(content string) []string {
	matches := p.apiEndpointRegex.FindAllString(content, -1)
	
	var filtered []string
	for _, match := range matches {
		// Filter out short paths and .dart files
		if len(match) > 3 && !strings.Contains(strings.ToLower(match), ".dart") {
			filtered = append(filtered, match)
		}
	}
	
	return uniqueStrings(filtered)
}

// ExtractPackages finds Flutter package names
func (p *PatternExtractor) ExtractPackages(content string, excludeAppPackage string) []string {
	matches := p.packageRegex.FindAllStringSubmatch(content, -1)
	
	var packages []string
	for _, match := range matches {
		if len(match) > 1 && match[1] != excludeAppPackage {
			packages = append(packages, match[1])
		}
	}
	
	return uniqueStrings(packages)
}

// ExtractAppPackageName finds the main app package name
func (p *PatternExtractor) ExtractAppPackageName(content string) string {
	re := regexp.MustCompile(`package:([^/]+)/.*main\.dart`)
	matches := re.FindStringSubmatch(content)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

// ExtractAppPackagePaths finds all paths for the app package
func (p *PatternExtractor) ExtractAppPackagePaths(content, packageName string) []string {
	if packageName == "" {
		return []string{}
	}
	
	re := regexp.MustCompile(`package:` + regexp.QuoteMeta(packageName) + `/[^"'\s]+\.dart`)
	matches := re.FindAllString(content, -1)
	return uniqueStrings(matches)
}

// ExtractSQLCommands finds SQL commands
func (p *PatternExtractor) ExtractSQLCommands(content string) []string {
	matches := p.sqlCommandRegex.FindAllString(content, -1)
	return uniqueStrings(matches)
}

// ExtractSQLiteDatabases finds SQLite database file references
func (p *PatternExtractor) ExtractSQLiteDatabases(content string) []string {
	matches := p.sqliteDBRegex.FindAllString(content, -1)
	return uniqueStrings(matches)
}

// Helper functions

func uniqueStrings(slice []string) []string {
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

func filterEmails(emails []string) []string {
	var filtered []string
	for _, email := range emails {
		// Filter out emails starting with underscore
		if !strings.HasPrefix(email, "_") {
			filtered = append(filtered, email)
		}
	}
	return filtered
}

func containsDigit(s string) bool {
	for _, r := range s {
		if r >= '0' && r <= '9' {
			return true
		}
	}
	return false
}

// ExtractDomains extracts all unique domains from URLs
func (p *PatternExtractor) ExtractDomains(content string) []string {
	urls := p.urlRegex.FindAllString(content, -1)
	domainSet := make(map[string]bool)
	
	for _, url := range urls {
		// Extract domain from URL
		parts := strings.Split(url, "://")
		if len(parts) > 1 {
			domain := strings.Split(parts[1], "/")[0]
			domain = strings.Split(domain, ":")[0] // Remove port
			if domain != "" && !strings.Contains(domain, " ") {
				// Validate domain
				if valid, _ := p.domainValidator.ValidateDomain(domain); valid {
					domainSet[domain] = true
				}
			}
		}
	}
	
	// Also find standalone domains
	domains := p.domainRegex.FindAllString(content, -1)
	for _, domain := range domains {
		if !strings.HasSuffix(domain, ".dart") && !strings.HasPrefix(domain, "package.") {
			// Validate domain
			if valid, _ := p.domainValidator.ValidateDomain(domain); valid {
				domainSet[domain] = true
			}
		}
	}
	
	var result []string
	for domain := range domainSet {
		result = append(result, domain)
	}
	return result
}

// ExtractEndpointsWithDomain extracts API endpoints with their domains
func (p *PatternExtractor) ExtractEndpointsWithDomain(content string, urls map[string][]string) []models.Endpoint {
	var endpoints []models.Endpoint
	seen := make(map[string]bool)
	
	// Process all URLs to extract endpoints
	allURLs := append(urls["http"], urls["https"]...)
	allURLs = append(allURLs, urls["other"]...)
	
	for _, url := range allURLs {
		parts := strings.Split(url, "://")
		if len(parts) < 2 {
			continue
		}
		
		remainder := parts[1]
		slashIdx := strings.Index(remainder, "/")
		if slashIdx == -1 {
			continue
		}
		
		domain := remainder[:slashIdx]
		path := remainder[slashIdx:]
		
		key := domain + path
		if !seen[key] {
			seen[key] = true
			endpoints = append(endpoints, models.Endpoint{
				URL:    url,
				Domain: domain,
				Path:   path,
			})
		}
	}
	
	return endpoints
}

// ExtractEndpointsNoDomain extracts potential endpoint paths without domains
func (p *PatternExtractor) ExtractEndpointsNoDomain(content string) []string {
	matches := p.apiEndpointRegex.FindAllString(content, -1)
	
	var filtered []string
	for _, match := range matches {
		if p.endpointValidator.ValidateEndpoint(match) {
			filtered = append(filtered, match)
		}
	}
	
	return uniqueStrings(filtered)
}

// ExtractHTTPRequests extracts potential HTTP request patterns
func (p *PatternExtractor) ExtractHTTPRequests(content string) []models.HTTPRequest {
	var requests []models.HTTPRequest
	
	// Look for method patterns followed by URLs
	lines := strings.Split(content, "\n")
	for i, line := range lines {
		methods := p.httpMethodRegex.FindAllString(line, -1)
		urls := p.urlRegex.FindAllString(line, -1)
		
		if len(methods) > 0 && len(urls) > 0 {
			request := models.HTTPRequest{
				Method: methods[0],
				URL:    urls[0],
				Headers: make(map[string]string),
			}
			
			// Check surrounding lines for headers
			for j := i - 2; j < i+3 && j < len(lines) && j >= 0; j++ {
				headers := p.headerRegex.FindAllStringSubmatch(lines[j], -1)
				for _, h := range headers {
					if len(h) > 2 {
						request.Headers[h[1]] = h[2]
					}
				}
			}
			
			requests = append(requests, request)
		}
	}
	
	return requests
}

// ExtractRequestHeaders extracts potential HTTP headers
func (p *PatternExtractor) ExtractRequestHeaders(content string) []models.RequestHeader {
	matches := p.headerRegex.FindAllStringSubmatch(content, -1)
	
	var headers []models.RequestHeader
	seen := make(map[string]bool)
	
	for _, match := range matches {
		if len(match) > 2 {
			key := match[1] + ":" + match[2]
			if !seen[key] {
				seen[key] = true
				// Validate header using header validator
				if valid, _ := p.headerValidator.ValidateHeader(match[1], match[2]); valid {
					headers = append(headers, models.RequestHeader{
						Name:  match[1],
						Value: match[2],
					})
				}
			}
		}
	}
	
	return headers
}

// ExtractImports extracts import statements (Dart/Flutter)
func (p *PatternExtractor) ExtractImports(content string) []string {
	matches := p.importRegex.FindAllStringSubmatch(content, -1)
	
	var imports []string
	for _, match := range matches {
		if len(match) > 1 {
			imports = append(imports, match[1])
		}
	}
	
	return uniqueStrings(imports)
}

// ExtractMethodChannels finds Flutter MethodChannel names
func (p *PatternExtractor) ExtractMethodChannels(content string) []string {
	matches := p.methodChannelRegex.FindAllStringSubmatch(content, -1)
	var out []string
	for _, m := range matches {
		if len(m) > 1 {
			out = append(out, m[1])
		}
	}
	return uniqueStrings(out)
}

// DetectServiceKeys detects known service keys in content (e.g., Stripe pk_ keys)
func (p *PatternExtractor) DetectServiceKeys(content string) (stripeKeys []string) {
	for _, m := range p.stripeKeyRegex.FindAllString(content, -1) {
		stripeKeys = append(stripeKeys, m)
	}
	return uniqueStrings(stripeKeys)
}

// ExtractIPAddresses finds IP addresses in content
func (p *PatternExtractor) ExtractIPAddresses(content string) []string {
	matches := p.ipRegex.FindAllString(content, -1)
	var validated []string
	for _, ip := range matches {
		if valid, _, category := p.ipValidator.ValidateIP(ip); valid && category != "loopback" && category != "reserved" {
			validated = append(validated, ip)
		}
	}
	return uniqueStrings(validated)
}

// DetectUIComponents finds UI library usage (Lottie, Syncfusion, etc.)
func (p *PatternExtractor) DetectUIComponents(content string, visualAssets []models.FileInfo) map[string]interface{} {
	result := make(map[string]interface{})
	var components []string
	
	// Check for Lottie
	hasLottie := p.lottieRegex.MatchString(content)
	if hasLottie {
		components = append(components, "Lottie Animations")
	}
	
	// Check for Syncfusion
	if p.syncfusionRegex.MatchString(content) {
		components = append(components, "Syncfusion Charts/Widgets")
	}
	
	// Count .json files in assets (potential Lottie files)
	var lottieFiles []string
	for _, f := range visualAssets {
		if strings.HasSuffix(strings.ToLower(f.Name), ".json") {
			lottieFiles = append(lottieFiles, f.Name)
		}
	}
	
	result["ui_libraries"] = components
	result["lottie_files"] = lottieFiles
	result["lottie_count"] = len(lottieFiles)
	
	return result
}
