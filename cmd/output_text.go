package cmd

import (
	"fmt"

	models "github.com/flutterguard/flutterguard-cli/models"
)

func formatTextReport(results *models.Results) string {
	var report string

	// Header with style
	report += "\n╔════════════════════════════════════════════╗\n"
	report += "║    🔍 FlutterGuard Analysis Report         ║\n"
	report += "╚════════════════════════════════════════════╝\n\n"

	// App Information
	if results.AppInfo.PackageName != "" {
		report += "📱 App Information\n"
		report += "─────────────────────────────────────────────\n"
		report += fmt.Sprintf("  Package:     %s\n", results.AppInfo.PackageName)
		report += fmt.Sprintf("  Version:     %s (%s)\n", results.AppInfo.VersionName, results.AppInfo.VersionCode)
		report += fmt.Sprintf("  SDK Target:  %d (min: %s)\n", parseSDK(results.AppInfo.TargetSDK), results.AppInfo.MinSDKVersion)
		report += "\n"
	}

	// Certificate Info
	if results.CertificateInfo != nil && len(results.CertificateInfo.Certificates) > 0 {
		report += "📜 Certificate Information\n"
		report += "─────────────────────────────────────────────\n"
		c := results.CertificateInfo.Certificates[0]
		report += fmt.Sprintf("  File:        %s\n", c.FileName)
		if c.IsSelfSigned {
			report += "  Status:      ⚠️  Self-signed\n"
		} else {
			report += "  Status:      ✅ Properly signed\n"
		}
		if c.IsExpired {
			report += "  Expiry:      ❌ Expired\n"
		} else {
			report += fmt.Sprintf("  Valid Until: %s\n", c.ValidTo)
		}
		report += "\n"
	}

	// Emails
	if len(results.Emails) > 0 {
		report += fmt.Sprintf("📧 Emails (%d found)\n", len(results.Emails))
		report += "─────────────────────────────────────────────\n"
		for i, email := range results.Emails {
			if i < 8 {
				report += fmt.Sprintf("  • %s\n", email)
			}
		}
		if len(results.Emails) > 8 {
			report += fmt.Sprintf("  ... and %d more\n", len(results.Emails)-8)
		}
		report += "\n"
	}

	// Domains
	if len(results.Domains) > 0 {
		report += fmt.Sprintf("🌐 Domains (%d found)\n", len(results.Domains))
		report += "─────────────────────────────────────────────\n"
		for i, domain := range results.Domains {
			if i < 8 {
				report += fmt.Sprintf("  • %s\n", domain)
			}
		}
		if len(results.Domains) > 8 {
			report += fmt.Sprintf("  ... and %d more\n", len(results.Domains)-8)
		}
		report += "\n"
	}

	// API Endpoints
	if len(results.APIEndpoints) > 0 {
		report += fmt.Sprintf("🔌 API Endpoints (%d found)\n", len(results.APIEndpoints))
		report += "─────────────────────────────────────────────\n"
		for i, endpoint := range results.APIEndpoints {
			if i < 8 {
				report += fmt.Sprintf("  • [%s] %s\n", endpoint.Method, endpoint.URL)
			}
		}
		if len(results.APIEndpoints) > 8 {
			report += fmt.Sprintf("  ... and %d more\n", len(results.APIEndpoints)-8)
		}
		report += "\n"
	}

	// Hardcoded Keys
	if len(results.HardcodedKeys) > 0 {
		report += fmt.Sprintf("🔑 Secrets Found (%d)\n", len(results.HardcodedKeys))
		report += "─────────────────────────────────────────────\n"
		for i, key := range results.HardcodedKeys {
			if i < 5 {
				report += fmt.Sprintf("  • %s\n", key)
			}
		}
		if len(results.HardcodedKeys) > 5 {
			report += fmt.Sprintf("  ... and %d more (check hardcoded_keys.txt)\n", len(results.HardcodedKeys)-5)
		}
		report += "\n"
	}

	// Firebase
	if results.Firebase != nil {
		report += "🔥 Firebase Configuration\n"
		report += "─────────────────────────────────────────────\n"
		report += fmt.Sprintf("  Project ID:     %s\n", results.Firebase.ProjectID)
		report += fmt.Sprintf("  Storage Bucket: %s\n", results.Firebase.StorageBucket)
		if results.Firebase.APIKeyMasked != "" {
			report += fmt.Sprintf("  API Key:        %s\n", results.Firebase.APIKeyMasked)
		}
		report += "\n"
	}

	// Services
	if len(results.Services) > 0 {
		report += fmt.Sprintf("🔗 Third-Party Services (%d)\n", len(results.Services))
		report += "─────────────────────────────────────────────\n"
		for i, svc := range results.Services {
			if i < 5 {
				report += fmt.Sprintf("  • %s", svc.Name)
				if len(svc.Domains) > 0 {
					report += fmt.Sprintf(" (%d domain(s))", len(svc.Domains))
				}
				report += "\n"
			}
		}
		if len(results.Services) > 5 {
			report += fmt.Sprintf("  ... and %d more\n", len(results.Services)-5)
		}
		report += "\n"
	}

	// Permissions
	if len(results.Permissions) > 0 {
		dangerousCount := 0
		for _, perm := range results.Permissions {
			if perm.Dangerous {
				dangerousCount++
			}
		}
		report += fmt.Sprintf("🛡️  Permissions (%d total)\n", len(results.Permissions))
		report += "─────────────────────────────────────────────\n"
		report += fmt.Sprintf("  Dangerous: %d  |  Normal: %d\n", dangerousCount, len(results.Permissions)-dangerousCount)
		report += "\n"
	}

	// Packages
	if len(results.Packages) > 0 {
		report += fmt.Sprintf("📚 Packages (%d)\n", len(results.Packages))
		report += "─────────────────────────────────────────────\n"
		for i, pkg := range results.Packages {
			if i < 8 {
				report += fmt.Sprintf("  • %s@%s\n", pkg.Name, pkg.Version)
			}
		}
		if len(results.Packages) > 8 {
			report += fmt.Sprintf("  ... and %d more\n", len(results.Packages)-8)
		}
		report += "\n"
	}

	report += "╔════════════════════════════════════════════╗\n"
	report += "║ 💡 Use --outDir for detailed reports      ║\n"
	report += "║ 📊 Use --format=json for full data        ║\n"
	report += "╚════════════════════════════════════════════╝\n"

	return report
}

func parseSDK(sdkStr string) int {
	// Try to parse SDK as int
	var sdk int
	fmt.Sscanf(sdkStr, "%d", &sdk)
	return sdk
}

