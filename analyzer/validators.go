package analyzer

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// EmailValidator validates and categorizes email addresses
type EmailValidator struct {
	emailRegex *regexp.Regexp
	validateDNS bool
}

func NewEmailValidator(validateDNS bool) *EmailValidator {
	return &EmailValidator{
		emailRegex: regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`),
		validateDNS: validateDNS,
	}
}

// ValidateEmail validates email format and domain with DNS verification
func (ev *EmailValidator) ValidateEmail(email string) bool {
	email = strings.TrimSpace(email)
	
	// Basic format validation
	if !ev.emailRegex.MatchString(email) {
		return false
	}
	
	// Extract domain
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return false
	}
	
	local := parts[0]
	domain := parts[1]
	
	// Filter out obfuscated/code patterns in local part
	if strings.Contains(local, "@") || strings.Contains(local, "_") && len(local) > 20 {
		return false
	}
	
	// Filter out invalid patterns
	invalidPatterns := []string{
		".dart", ".java", ".kt", ".xml", ".apk",
		"example.com", "test.com", "localhost",
		".webp", ".png", ".jpg",
	}
	
	for _, pattern := range invalidPatterns {
		if strings.Contains(strings.ToLower(domain), pattern) {
			return false
		}
	}
	
	// Verify domain has valid DNS MX or A records (optional)
	if ev.validateDNS {
		return ev.verifyDomainDNS(domain)
	}
	return true
}

// verifyDomainDNS checks if domain has valid DNS records
func (ev *EmailValidator) verifyDomainDNS(domain string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	
	// Check for MX records first (email-specific)
	mxRecords, err := net.DefaultResolver.LookupMX(ctx, domain)
	if err == nil && len(mxRecords) > 0 {
		return true
	}
	
	// Fallback to A/AAAA records
	addrs, err := net.DefaultResolver.LookupHost(ctx, domain)
	return err == nil && len(addrs) > 0
}

// URLValidator validates and categorizes URLs
type URLValidator struct{ validateDNS bool }

func NewURLValidator(validateDNS bool) *URLValidator {
	return &URLValidator{validateDNS: validateDNS}
}

// ValidateURL validates URL format and checks reachability
func (uv *URLValidator) ValidateURL(rawURL string) (bool, string) {
	// Parse URL
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return false, ""
	}
	
	// Must have scheme and host
	if parsedURL.Scheme == "" || parsedURL.Host == "" {
		return false, ""
	}
	
	// Filter out invalid patterns
	invalidPatterns := []string{
		".dart", "package:", "asset:", ".webp", ".png",
	}
	
	for _, pattern := range invalidPatterns {
		if strings.Contains(strings.ToLower(rawURL), pattern) {
			return false, ""
		}
	}
	
	// Only validate HTTP/HTTPS URLs
	protocol := strings.ToLower(parsedURL.Scheme)
	if protocol == "http" || protocol == "https" {
		// Verify host resolves (optional)
		if uv.validateDNS {
			if !uv.verifyHostDNS(parsedURL.Host) {
				return false, ""
			}
		}
	}
	
	return true, protocol
}

// verifyHostDNS checks if host resolves
func (uv *URLValidator) verifyHostDNS(host string) bool {
	// Remove port if present
	if strings.Contains(host, ":") {
		host, _, _ = net.SplitHostPort(host)
	}
	
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	
	addrs, err := net.DefaultResolver.LookupHost(ctx, host)
	return err == nil && len(addrs) > 0
}

// DomainValidator validates and categorizes domains
type DomainValidator struct{ validateDNS bool }

func NewDomainValidator(validateDNS bool) *DomainValidator {
	return &DomainValidator{validateDNS: validateDNS}
}

// ValidateDomain validates domain format, DNS, and categorizes by type
func (dv *DomainValidator) ValidateDomain(domain string) (bool, string) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	
	// Filter out invalid patterns
	if strings.Contains(domain, ".dart") ||
		strings.Contains(domain, "package.") ||
		strings.Contains(domain, " ") ||
		strings.Contains(domain, ".webp") ||
		strings.Contains(domain, ".png") ||
		strings.Contains(domain, "@") ||
		len(domain) < 3 {
		return false, ""
	}
	
	// Check basic format
	domainRegex := regexp.MustCompile(`^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)*$`)
	if !domainRegex.MatchString(domain) {
		return false, ""
	}
	
	// Must have at least one dot (TLD)
	if !strings.Contains(domain, ".") {
		return false, ""
	}
	
	// Verify DNS resolves (optional)
	if dv.validateDNS {
		if !dv.verifyDomainDNS(domain) {
			return false, ""
		}
	}
	
	// Categorize domain type
	category := dv.categorizeDomain(domain)
	return true, category
}

// verifyDomainDNS checks if domain resolves via DNS
func (dv *DomainValidator) verifyDomainDNS(domain string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	
	addrs, err := net.DefaultResolver.LookupHost(ctx, domain)
	return err == nil && len(addrs) > 0
}

func (dv *DomainValidator) categorizeDomain(domain string) string {
	// Reserved/Private domains
	reservedDomains := []string{"localhost", "example.com", "test.com", "invalid"}
	for _, reserved := range reservedDomains {
		if domain == reserved {
			return "reserved"
		}
	}
	
	// Private IP ranges domains
	if strings.HasPrefix(domain, "192.168.") || strings.HasPrefix(domain, "10.") || strings.HasPrefix(domain, "172.") {
		return "private"
	}
	
	// Cloud/CDN services
	cloudServices := []string{
		".amazonaws.com", ".cloudfront.net", ".googleusercontent.com",
		".azure.com", ".cloudflare.com", ".fastly.net",
	}
	for _, service := range cloudServices {
		if strings.HasSuffix(domain, service) {
			return "cloud"
		}
	}
	
	return "public"
}

// IPValidator validates and categorizes IP addresses
type IPValidator struct{}

func NewIPValidator() *IPValidator {
	return &IPValidator{}
}

// ValidateIP validates IP format (IPv4/IPv6) and categorizes
func (ipv *IPValidator) ValidateIP(ipStr string) (bool, string, string) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false, "", ""
	}
	
	var ipType, category string
	
	// Determine IP version
	if ip.To4() != nil {
		ipType = "IPv4"
		category = ipv.categorizeIPv4(ip)
	} else {
		ipType = "IPv6"
		category = ipv.categorizeIPv6(ip)
	}
	
	return true, ipType, category
}

func (ipv *IPValidator) categorizeIPv4(ip net.IP) string {
	ipv4 := ip.To4()
	
	// Private ranges
	if ipv4[0] == 10 {
		return "private"
	}
	if ipv4[0] == 172 && ipv4[1] >= 16 && ipv4[1] <= 31 {
		return "private"
	}
	if ipv4[0] == 192 && ipv4[1] == 168 {
		return "private"
	}
	
	// Loopback
	if ipv4[0] == 127 {
		return "loopback"
	}
	
	// Link-local
	if ipv4[0] == 169 && ipv4[1] == 254 {
		return "link-local"
	}
	
	// Multicast
	if ipv4[0] >= 224 && ipv4[0] <= 239 {
		return "multicast"
	}
	
	// Reserved
	if ipv4[0] >= 240 {
		return "reserved"
	}
	
	return "public"
}

func (ipv *IPValidator) categorizeIPv6(ip net.IP) string {
	// Loopback
	if ip.IsLoopback() {
		return "loopback"
	}
	
	// Link-local
	if ip.IsLinkLocalUnicast() {
		return "link-local"
	}
	
	// Multicast
	if ip.IsMulticast() {
		return "multicast"
	}
	
	// Private (ULA)
	if ip[0] == 0xfd || ip[0] == 0xfc {
		return "private"
	}
	
	return "public"
}

// PhoneValidator validates phone numbers intelligently
type PhoneValidator struct{}

func NewPhoneValidator() *PhoneValidator {
	return &PhoneValidator{}
}

// ValidatePhone validates phone number format and filters invalid patterns
func (pv *PhoneValidator) ValidatePhone(phone string) bool {
	// Clean the phone number
	cleaned := strings.Map(func(r rune) rune {
		if (r >= '0' && r <= '9') || r == '+' {
			return r
		}
		return -1
	}, phone)
	
	// Count digits
	digitCount := 0
	for _, c := range cleaned {
		if c >= '0' && c <= '9' {
			digitCount++
		}
	}
	
	// Valid international phone: 7-15 digits
	if digitCount < 7 || digitCount > 15 {
		return false
	}
	
	// Filter out invalid patterns
	invalidPatterns := []string{
		"0000000", "1111111", "2222222", "3333333",
		"4444444", "5555555", "6666666", "7777777",
		"8888888", "9999999", "1234567", "7654321",
	}
	
	for _, pattern := range invalidPatterns {
		if strings.Contains(cleaned, pattern) {
			return false
		}
	}
	
	// Check for sequential digits (too many)
	sequentialCount := 1
	var lastDigit rune = -1
	for _, c := range cleaned {
		if c >= '0' && c <= '9' {
			if lastDigit != -1 && c == lastDigit+1 {
				sequentialCount++
				if sequentialCount > 5 {
					return false
				}
			} else {
				sequentialCount = 1
			}
			lastDigit = c
		}
	}
	
	// Check for too many repeated digits
	digitCounts := make(map[rune]int)
	for _, c := range cleaned {
		if c >= '0' && c <= '9' {
			digitCounts[c]++
		}
	}
	
	for _, count := range digitCounts {
		if float64(count)/float64(digitCount) > 0.6 {
			return false
		}
	}
	
	// Check if it looks like a timestamp or version number
	if digitCount >= 10 {
		// Try parsing as timestamp (seconds since epoch)
		if num, err := strconv.ParseInt(cleaned, 10, 64); err == nil {
			// Timestamps for years 2000-2030 are in range [946684800, 1893456000]
			if num > 946684800 && num < 1893456000 {
				return false
			}
		}
	}
	
	// Check if it's a common test number
	testNumbers := []string{
		"+15555551234", "5555551234", "+12125551234",
		"1234567890", "+11234567890",
	}
	
	for _, test := range testNumbers {
		if cleaned == strings.ReplaceAll(test, "+", "") || cleaned == test {
			return false
		}
	}
	
	return true
}

// EndpointValidator validates API endpoints
type EndpointValidator struct{}

func NewEndpointValidator() *EndpointValidator {
	return &EndpointValidator{}
}

// ValidateEndpoint validates endpoint format
func (ev *EndpointValidator) ValidateEndpoint(endpoint string) bool {
	// Must start with /
	if !strings.HasPrefix(endpoint, "/") {
		return false
	}
	
	// Filter out file extensions
	invalidExtensions := []string{
		".dart", ".java", ".kt", ".xml", ".json", ".yaml",
		".png", ".jpg", ".jpeg", ".gif", ".svg",
	}
	
	lowerEndpoint := strings.ToLower(endpoint)
	for _, ext := range invalidExtensions {
		if strings.HasSuffix(lowerEndpoint, ext) {
			return false
		}
	}
	
	// Too short
	if len(endpoint) < 2 {
		return false
	}
	
	// Contains spaces
	if strings.Contains(endpoint, " ") {
		return false
	}
	
	return true
}

// ValidateFullEndpointURL validates and checks connectivity for full endpoint URLs
func (ev *EndpointValidator) ValidateFullEndpointURL(fullURL string) bool {
	// Parse URL
	parsedURL, err := url.Parse(fullURL)
	if err != nil {
		return false
	}
	
	// Must be HTTP or HTTPS
	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return false
	}
	
	// Must have a host
	if parsedURL.Host == "" {
		return false
	}
	
	// Verify host DNS resolution
	host := parsedURL.Host
	if colonIdx := strings.Index(host, ":"); colonIdx != -1 {
		host = host[:colonIdx]
	}
	
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	
	_, err = net.DefaultResolver.LookupHost(ctx, host)
	if err != nil {
		return false
	}
	
	// Optional: Try HEAD request to verify endpoint is reachable
	// This is more aggressive validation but can catch dead endpoints
	headCtx, headCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer headCancel()
	
	req, err := http.NewRequestWithContext(headCtx, http.MethodHead, fullURL, nil)
	if err != nil {
		return false
	}
	
	client := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Allow redirects but limit to 3
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
	
	resp, err := client.Do(req)
	if err != nil {
		// If HEAD fails, endpoint might not support it, so don't reject
		// DNS verification is the primary check
		return true
	}
	defer resp.Body.Close()
	
	// Accept any non-5xx status code (server available)
	return resp.StatusCode < 500
}

// HTTPHeaderValidator validates HTTP headers
type HTTPHeaderValidator struct{}

func NewHTTPHeaderValidator() *HTTPHeaderValidator {
	return &HTTPHeaderValidator{}
}

// ValidateHeader validates header format and categorizes
func (hhv *HTTPHeaderValidator) ValidateHeader(name, value string) (bool, string) {
	name = strings.TrimSpace(name)
	value = strings.TrimSpace(value)
	
	if name == "" || value == "" {
		return false, ""
	}
	
	// Common security headers
	securityHeaders := map[string]bool{
		"authorization":             true,
		"www-authenticate":          true,
		"proxy-authenticate":        true,
		"proxy-authorization":       true,
		"content-security-policy":   true,
		"x-frame-options":           true,
		"x-content-type-options":    true,
		"strict-transport-security": true,
		"x-xss-protection":          true,
	}
	
	lowerName := strings.ToLower(name)
	if securityHeaders[lowerName] {
		return true, "security"
	}
	
	// Common standard headers
	standardHeaders := map[string]bool{
		"content-type":     true,
		"content-length":   true,
		"accept":           true,
		"accept-encoding":  true,
		"accept-language":  true,
		"user-agent":       true,
		"referer":          true,
		"host":             true,
		"connection":       true,
		"cache-control":    true,
		"pragma":           true,
		"expires":          true,
		"if-modified-since": true,
		"if-none-match":    true,
		"etag":             true,
	}
	
	if standardHeaders[lowerName] {
		return true, "standard"
	}
	
	// Custom headers (usually start with X-)
	if strings.HasPrefix(lowerName, "x-") {
		return true, "custom"
	}
	
	return true, "other"
}

// ServiceDetector detects various cloud and third-party services
type ServiceDetector struct{}

func NewServiceDetector() *ServiceDetector {
	return &ServiceDetector{}
}

// DetectService detects service based on domain or package
func (sd *ServiceDetector) DetectService(domain, packageName, content string) *ServiceDetection {
	// Check for AWS
	if sd.matchesAWS(domain, content) {
		return &ServiceDetection{
			Name:    "AWS",
			Type:    "cloud",
			Domains: []string{"amazonaws.com", "aws.amazon.com"},
		}
	}
	
	// Check for GCP
	if sd.matchesGCP(domain, content) {
		return &ServiceDetection{
			Name:    "Google Cloud Platform",
			Type:    "cloud",
			Domains: []string{"googleapis.com", "googleusercontent.com"},
		}
	}
	
	// Check for Azure
	if sd.matchesAzure(domain, content) {
		return &ServiceDetection{
			Name:    "Microsoft Azure",
			Type:    "cloud",
			Domains: []string{"azure.com", "windows.net"},
		}
	}
	
	return nil
}

func (sd *ServiceDetector) matchesAWS(domain, content string) bool {
	awsIndicators := []string{
		"amazonaws.com", "aws.amazon.com", "s3.amazonaws",
		"dynamodb", "cognito", "lambda.aws",
	}
	
	for _, indicator := range awsIndicators {
		if strings.Contains(strings.ToLower(domain), indicator) ||
			strings.Contains(strings.ToLower(content), indicator) {
			return true
		}
	}
	return false
}

func (sd *ServiceDetector) matchesGCP(domain, content string) bool {
	gcpIndicators := []string{
		"googleapis.com", "googleusercontent.com",
		"gcp", "google-cloud", "firestore", "cloud.google",
	}
	
	for _, indicator := range gcpIndicators {
		if strings.Contains(strings.ToLower(domain), indicator) ||
			strings.Contains(strings.ToLower(content), indicator) {
			return true
		}
	}
	return false
}

func (sd *ServiceDetector) matchesAzure(domain, content string) bool {
	azureIndicators := []string{
		"azure.com", "windows.net", "azurewebsites",
		"azure-api", "servicebus.windows",
	}
	
	for _, indicator := range azureIndicators {
		if strings.Contains(strings.ToLower(domain), indicator) ||
			strings.Contains(strings.ToLower(content), indicator) {
			return true
		}
	}
	return false
}

type ServiceDetection struct {
	Name    string
	Type    string
	Domains []string
}
