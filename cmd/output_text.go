package cmd

import (
	"fmt"

	models "github.com/flutterguard/flutterguard-cli/models"
)

func formatTextReport(results *models.Results) string {
	var report string

	report += "=================================================\n"
	report += "           FlutterGuard Analysis Report         \n"
	report += "=================================================\n\n"

	// App Information
	if results.AppInfo.PackageName != "" {
		report += fmt.Sprintf("Package Name: %s\n", results.AppInfo.PackageName)
		report += fmt.Sprintf("Version: %s (%s)\n", results.AppInfo.VersionName, results.AppInfo.VersionCode)
		report += fmt.Sprintf("Min SDK: %s | Target SDK: %s\n\n", results.AppInfo.MinSDKVersion, results.AppInfo.TargetSDK)
	}

	// Certificate Info
	if results.CertificateInfo != nil {
		report += "📜 Certificate Information:\n"
		if len(results.CertificateInfo.Certificates) > 0 {
			c := results.CertificateInfo.Certificates[0]
			report += fmt.Sprintf("  File: %s\n", c.FileName)
			report += fmt.Sprintf("  Issuer: %s\n", c.Issuer)
			report += fmt.Sprintf("  Subject: %s\n", c.Subject)
			report += fmt.Sprintf("  Valid: %s to %s\n", c.ValidFrom, c.ValidTo)
			if c.IsSelfSigned {
				report += "  Note: Self-signed certificate\n"
			}
			if c.IsExpired {
				report += "  Warning: Certificate expired\n"
			}
		}
		if len(results.CertificateInfo.SecurityNotes) > 0 {
			report += "  Security Notes:\n"
			for _, n := range results.CertificateInfo.SecurityNotes {
				report += fmt.Sprintf("    - %s\n", n)
			}
		}
		report += "\n"
	}

	// Emails
	if len(results.Emails) > 0 {
		report += fmt.Sprintf("📧 Emails Found: %d\n", len(results.Emails))
		for i, email := range results.Emails {
			if i < 10 { // Limit display
				report += fmt.Sprintf("  - %s\n", email)
			}
		}
		if len(results.Emails) > 10 {
			report += fmt.Sprintf("  ... and %d more\n", len(results.Emails)-10)
		}
		report += "\n"
	}

	// Domains
	if len(results.Domains) > 0 {
		report += fmt.Sprintf("🌐 Domains Found: %d\n", len(results.Domains))
		for i, domain := range results.Domains {
			if i < 10 {
				report += fmt.Sprintf("  - %s\n", domain)
			}
		}
		if len(results.Domains) > 10 {
			report += fmt.Sprintf("  ... and %d more\n", len(results.Domains)-10)
		}
		report += "\n"
	}

	// API Endpoints
	if len(results.APIEndpoints) > 0 {
		report += fmt.Sprintf("🔗 API Endpoints Found: %d\n", len(results.APIEndpoints))
		for i, endpoint := range results.APIEndpoints {
			if i < 10 {
				report += fmt.Sprintf("  - [%s] %s\n", endpoint.Method, endpoint.URL)
			}
		}
		if len(results.APIEndpoints) > 10 {
			report += fmt.Sprintf("  ... and %d more\n", len(results.APIEndpoints)-10)
		}
		report += "\n"
	}

	// Hardcoded Keys
	if len(results.HardcodedKeys) > 0 {
		report += fmt.Sprintf("🔑 Hardcoded Keys Found: %d\n", len(results.HardcodedKeys))
		for i, key := range results.HardcodedKeys {
			if i < 5 {
				report += fmt.Sprintf("  - %s\n", key)
			}
		}
		if len(results.HardcodedKeys) > 5 {
			report += fmt.Sprintf("  ... and %d more\n", len(results.HardcodedKeys)-5)
		}
		report += "\n"
	}

	// Firebase
	if results.Firebase != nil {
		report += "🔥 Firebase Configuration:\n"
		report += fmt.Sprintf("  Project ID: %s\n", results.Firebase.ProjectID)
		report += fmt.Sprintf("  Storage Bucket: %s\n", results.Firebase.StorageBucket)
		if results.Firebase.APIKeyMasked != "" {
			report += fmt.Sprintf("  API Key: %s\n", results.Firebase.APIKeyMasked)
		}
		if len(results.Firebase.Endpoints) > 0 {
			report += "  Endpoints:\n"
			for _, e := range results.Firebase.Endpoints {
				report += fmt.Sprintf("    - %s\n", e)
			}
		}
		report += "\n"
	}

	// Services
	if len(results.Services) > 0 {
		report += fmt.Sprintf("⚙️  Third-Party Services: %d\n", len(results.Services))
		for _, svc := range results.Services {
			report += fmt.Sprintf("  - %s\n", svc.Name)
			if len(svc.Indicators) > 0 {
				report += "    Indicators:\n"
				for _, ind := range svc.Indicators {
					report += fmt.Sprintf("      - %s\n", ind)
				}
			}
			if len(svc.Domains) > 0 {
				report += "    Domains:\n"
				for _, d := range svc.Domains {
					report += fmt.Sprintf("      - %s\n", d)
				}
			}
			if len(svc.Keys) > 0 {
				report += "    Keys:\n"
				for _, k := range svc.Keys {
					report += fmt.Sprintf("      - %s\n", k)
				}
			}
		}
		report += "\n"
	}

	// Permissions
	if len(results.Permissions) > 0 {
		report += fmt.Sprintf("🔒 Permissions: %d\n", len(results.Permissions))
		dangerousCount := 0
		for _, perm := range results.Permissions {
			if perm.Dangerous {
				dangerousCount++
			}
		}
		report += fmt.Sprintf("  Dangerous: %d\n", dangerousCount)
		report += fmt.Sprintf("  Normal: %d\n\n", len(results.Permissions)-dangerousCount)
	}

	// Packages
	if len(results.Packages) > 0 {
		report += fmt.Sprintf("📦 Flutter Packages: %d\n", len(results.Packages))
		for i, pkg := range results.Packages {
			if i < 10 {
				report += fmt.Sprintf("  - %s %s\n", pkg.Name, pkg.Version)
			}
		}
		if len(results.Packages) > 10 {
			report += fmt.Sprintf("  ... and %d more\n", len(results.Packages)-10)
		}
		report += "\n"
	}

	report += "=================================================\n"
	report += "For full JSON report, use -format=json\n"
	report += "=================================================\n"

	return report
}
