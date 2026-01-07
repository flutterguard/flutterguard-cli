package analyzer

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	models "github.com/flutterguard/flutterguard-cli/models"
)

// CertificateAnalyzer handles extraction and analysis of APK certificates
type CertificateAnalyzer struct{}

func NewCertificateAnalyzer() *CertificateAnalyzer {
	return &CertificateAnalyzer{}
}

// IsAvailable checks if openssl command is available
func (c *CertificateAnalyzer) IsAvailable() bool {
	_, err := exec.LookPath("openssl")
	return err == nil
}

// AnalyzeCertificates extracts and analyzes certificates from META-INF directory
func (c *CertificateAnalyzer) AnalyzeCertificates(ctx context.Context, decompDir string) (*models.CertificateInfo, error) {
	if !c.IsAvailable() {
		return nil, fmt.Errorf("openssl command not available")
	}

	// Recursively find META-INF directory
	metaInfPath := findMetaINFDirectory(decompDir)
	if metaInfPath == "" {
		return nil, fmt.Errorf("META-INF directory not found")
	}

	certInfo := &models.CertificateInfo{
		Certificates: []models.Certificate{},
	}

	// Find all certificate files containing "CERT" in their name (case-insensitive)
	entries, err := os.ReadDir(metaInfPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read META-INF directory: %w", err)
	}

	var certFiles []string
	for _, entry := range entries {
		if !entry.IsDir() && strings.Contains(strings.ToUpper(entry.Name()), "CERT") {
			certFiles = append(certFiles, filepath.Join(metaInfPath, entry.Name()))
		}
	}

	if len(certFiles) == 0 {
		return nil, fmt.Errorf("no certificate files found in META-INF")
	}

	// Analyze each certificate file
	for _, certFile := range certFiles {
		cert, err := c.analyzeCertificateFile(ctx, certFile)
		if err != nil {
			// Log error but continue with other certificates
			certInfo.Errors = append(certInfo.Errors, fmt.Sprintf("Failed to analyze %s: %v", filepath.Base(certFile), err))
			continue
		}
		certInfo.Certificates = append(certInfo.Certificates, *cert)
	}

	// Generate security notes
	certInfo.SecurityNotes = c.generateSecurityNotes(certInfo.Certificates)

	return certInfo, nil
}

// analyzeCertificateFile analyzes a single certificate file using openssl
func (c *CertificateAnalyzer) analyzeCertificateFile(ctx context.Context, certFile string) (*models.Certificate, error) {
	cmd := exec.CommandContext(ctx, "openssl", "pkcs7", "-inform", "DER", "-print_certs", "-in", certFile)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("openssl failed: %w (stderr: %s)", err, stderr.String())
	}

	output := stdout.String()
	
	cert := &models.Certificate{
		FileName: filepath.Base(certFile),
		RawOutput: output,
	}

	// Parse certificate details
	c.parseCertificateDetails(cert, output)

	return cert, nil
}

// parseCertificateDetails parses openssl output to extract certificate information
func (c *CertificateAnalyzer) parseCertificateDetails(cert *models.Certificate, output string) {
	lines := strings.Split(output, "\n")
	
	for i, line := range lines {
		line = strings.TrimSpace(line)

		// Extract subject
		if strings.HasPrefix(line, "subject=") || strings.Contains(line, "Subject:") {
			if strings.HasPrefix(line, "subject=") {
				cert.Subject = strings.TrimPrefix(line, "subject=")
			} else if i+1 < len(lines) {
				cert.Subject = strings.TrimSpace(lines[i+1])
			}
		}

		// Extract issuer
		if strings.HasPrefix(line, "issuer=") || strings.Contains(line, "Issuer:") {
			if strings.HasPrefix(line, "issuer=") {
				cert.Issuer = strings.TrimPrefix(line, "issuer=")
			} else if i+1 < len(lines) {
				cert.Issuer = strings.TrimSpace(lines[i+1])
			}
		}

		// Extract validity dates
		if strings.Contains(line, "Not Before") || strings.Contains(line, "notBefore") {
			dateStr := extractDate(line)
			if dateStr != "" {
				cert.ValidFrom = dateStr
			}
		}
		if strings.Contains(line, "Not After") || strings.Contains(line, "notAfter") {
			dateStr := extractDate(line)
			if dateStr != "" {
				cert.ValidTo = dateStr
			}
		}

		// Extract serial number
		if strings.Contains(line, "Serial Number") || strings.Contains(line, "serial") {
			serialRe := regexp.MustCompile(`([0-9a-fA-F:]+)`)
			if match := serialRe.FindString(line); match != "" {
				cert.SerialNumber = match
			}
		}

		// Extract signature algorithm
		if strings.Contains(line, "Signature Algorithm") {
			parts := strings.Split(line, ":")
			if len(parts) > 1 {
				cert.SignatureAlgorithm = strings.TrimSpace(parts[1])
			}
		}

		// Extract public key algorithm and size
		if strings.Contains(line, "Public Key Algorithm") || strings.Contains(line, "Public-Key:") {
			if strings.Contains(line, "rsaEncryption") {
				cert.PublicKeyAlgorithm = "RSA"
			} else if strings.Contains(line, "ecPublicKey") || strings.Contains(line, "EC") {
				cert.PublicKeyAlgorithm = "EC"
			} else if strings.Contains(line, "dsaEncryption") {
				cert.PublicKeyAlgorithm = "DSA"
			}
		}
		if strings.Contains(line, "Public-Key:") {
			sizeRe := regexp.MustCompile(`\((\d+)\s+bit\)`)
			if match := sizeRe.FindStringSubmatch(line); len(match) > 1 {
				cert.PublicKeySize = match[1] + " bit"
			}
		}
	}

	// Extract CN (Common Name) from subject
	if cert.Subject != "" {
		cnRe := regexp.MustCompile(`CN\s*=\s*([^,]+)`)
		if match := cnRe.FindStringSubmatch(cert.Subject); len(match) > 1 {
			cert.CommonName = strings.TrimSpace(match[1])
		}
	}

	// Extract Organization from subject
	if cert.Subject != "" {
		orgRe := regexp.MustCompile(`O\s*=\s*([^,]+)`)
		if match := orgRe.FindStringSubmatch(cert.Subject); len(match) > 1 {
			cert.Organization = strings.TrimSpace(match[1])
		}
	}

	// Check if self-signed
	cert.IsSelfSigned = cert.Subject == cert.Issuer

	// Check if expired
	if cert.ValidTo != "" {
		cert.IsExpired = c.isCertificateExpired(cert.ValidTo)
	}
}

// extractDate extracts date string from certificate output
func extractDate(line string) string {
	// Try to find date patterns like "Jan 1 00:00:00 2024 GMT"
	dateRe := regexp.MustCompile(`([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4}\s+\w+)`)
	if match := dateRe.FindString(line); match != "" {
		return match
	}
	
	// Try ISO format
	isoRe := regexp.MustCompile(`\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}`)
	if match := isoRe.FindString(line); match != "" {
		return match
	}

	return ""
}

// isCertificateExpired checks if a certificate is expired
func (c *CertificateAnalyzer) isCertificateExpired(validTo string) bool {
	// Try parsing common date formats
	formats := []string{
		"Jan 2 15:04:05 2006 MST",
		"2006-01-02 15:04:05",
		time.RFC3339,
	}

	for _, format := range formats {
		if t, err := time.Parse(format, validTo); err == nil {
			return time.Now().After(t)
		}
	}

	return false
}

// generateSecurityNotes generates security analysis notes for certificates
func (c *CertificateAnalyzer) generateSecurityNotes(certs []models.Certificate) []string {
	var notes []string

	for _, cert := range certs {
		// Check for self-signed certificates
		if cert.IsSelfSigned {
			notes = append(notes, fmt.Sprintf("⚠️ Certificate '%s' is self-signed. This is common for debug builds but should not be used in production.", cert.CommonName))
		}

		// Check for expired certificates
		if cert.IsExpired {
			notes = append(notes, fmt.Sprintf("🔴 Certificate '%s' has expired (valid until %s). This APK may not install on newer Android versions.", cert.CommonName, cert.ValidTo))
		}

		// Check for weak signature algorithms
		if strings.Contains(strings.ToLower(cert.SignatureAlgorithm), "md5") ||
			strings.Contains(strings.ToLower(cert.SignatureAlgorithm), "sha1") {
			notes = append(notes, fmt.Sprintf("⚠️ Certificate '%s' uses weak signature algorithm '%s'. Consider upgrading to SHA-256 or higher.", cert.CommonName, cert.SignatureAlgorithm))
		}

		// Check for weak key sizes
		if cert.PublicKeyAlgorithm == "RSA" && strings.Contains(cert.PublicKeySize, "1024") {
			notes = append(notes, fmt.Sprintf("⚠️ Certificate '%s' uses weak RSA key size (1024 bit). Modern security standards recommend at least 2048 bits.", cert.CommonName))
		}

		// Check validity period
		if cert.ValidFrom != "" && cert.ValidTo != "" {
			validity := c.calculateValidityYears(cert.ValidFrom, cert.ValidTo)
			if validity > 25 {
				notes = append(notes, fmt.Sprintf("ℹ️ Certificate '%s' has a very long validity period (%d+ years). This is typical for debug/development certificates.", cert.CommonName, validity))
			}
		}

		// Check for generic/default names
		if strings.Contains(strings.ToLower(cert.CommonName), "android debug") ||
			strings.Contains(strings.ToLower(cert.CommonName), "unknown") {
			notes = append(notes, fmt.Sprintf("🔧 Certificate '%s' appears to be a debug certificate. This app should not be distributed publicly.", cert.CommonName))
		}
	}

	// Overall assessment
	if len(certs) == 0 {
		notes = append(notes, "❌ No certificates found. The APK signature may be corrupted.")
	} else if len(certs) == 1 {
		notes = append(notes, "✓ Single certificate found (standard configuration).")
	} else {
		notes = append(notes, fmt.Sprintf("ℹ️ Multiple certificates found (%d). This is unusual and may indicate repackaging.", len(certs)))
	}

	return notes
}

// calculateValidityYears calculates approximate years between two date strings
func (c *CertificateAnalyzer) calculateValidityYears(validFrom, validTo string) int {
	formats := []string{
		"Jan 2 15:04:05 2006 MST",
		"2006-01-02 15:04:05",
		time.RFC3339,
	}

	var fromTime, toTime time.Time
	var err error

	for _, format := range formats {
		fromTime, err = time.Parse(format, validFrom)
		if err == nil {
			break
		}
	}

	for _, format := range formats {
		toTime, err = time.Parse(format, validTo)
		if err == nil {
			break
		}
	}

	if fromTime.IsZero() || toTime.IsZero() {
		return 0
	}

	duration := toTime.Sub(fromTime)
	years := int(duration.Hours() / 24 / 365)
	return years
}

// findMetaINFDirectory recursively searches for META-INF directory in the decompiled folder
func findMetaINFDirectory(rootDir string) string {
	var foundPath string

	filepath.Walk(rootDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		// Check if this is a META-INF directory
		if info.IsDir() && strings.EqualFold(filepath.Base(path), "META-INF") {
			foundPath = path
			return filepath.SkipDir // Stop searching after finding first match
		}

		return nil
	})

	return foundPath
}
