package cmd

import (
	"fmt"
	"path/filepath"
	"strings"

	models "github.com/flutterguard/flutterguard-cli/models"
)

func formatMarkdownSummary(results *models.Results, allAssets []models.FileInfo) string {
	var md strings.Builder

	addGap := func() {
		md.WriteString("\n\n")
	}

	md.WriteString("# FlutterGuard Analysis Report\n\n")

	md.WriteString("## 📋 Table of Contents\n\n")
	md.WriteString("- [App Information](#app-information)\n")
	if results.CertificateInfo != nil {
		md.WriteString("- [Certificate Information](#certificate-information)\n")
	}
	if len(results.Emails) > 0 {
		md.WriteString("- [Emails](#emails) - [View File](emails.txt)\n")
	}
	if len(results.Domains) > 0 {
		md.WriteString("- [Domains](#domains) - [View File](domains.txt)\n")
	}
	allURLs := collectAllURLs(results)
	if len(allURLs) > 0 {
		md.WriteString("- [URLs](#urls) - [View File](urls.txt)\n")
	}
	if len(results.APIEndpoints) > 0 {
		md.WriteString("- [API Endpoints](#api-endpoints) - [View File](api_endpoints.txt)\n")
	}
	if len(results.HardcodedKeys) > 0 {
		md.WriteString("- [Hardcoded Keys](#hardcoded-keys) - [View File](hardcoded_keys.txt)\n")
	}
	if results.Firebase != nil {
		md.WriteString("- [Firebase Configuration](#firebase-configuration)\n")
	}
	if len(results.Services) > 0 {
		md.WriteString("- [Third-Party Services](#third-party-services) - [View File](services.txt)\n")
	}
	if len(results.Permissions) > 0 {
		md.WriteString("- [Permissions](#permissions) - [View File](permissions.txt)\n")
	}
	if len(results.Packages) > 0 {
		md.WriteString("- [Flutter Packages](#flutter-packages) - [View File](packages.txt)\n")
	}
	if len(allAssets) > 0 {
		md.WriteString("- [Assets](#assets) - [View Folder](assets/)\n")
	}
	if results.DecompiledDirPath != "" {
		md.WriteString("- [Decompiled APK](#decompiled-apk) - [View Folder](decompiled/)\n")
	}
	md.WriteString("\n---\n\n")

	md.WriteString("## 🎯 App Information\n\n")
	if results.AppInfo.PackageName != "" {
		md.WriteString(fmt.Sprintf("- **Package Name:** `%s`\n", results.AppInfo.PackageName))
		md.WriteString(fmt.Sprintf("- **Version:** %s (%s)\n", results.AppInfo.VersionName, results.AppInfo.VersionCode))
		md.WriteString(fmt.Sprintf("- **Min SDK:** %s\n", results.AppInfo.MinSDKVersion))
		md.WriteString(fmt.Sprintf("- **Target SDK:** %s\n", results.AppInfo.TargetSDK))
	}
	addGap()

	if results.CertificateInfo != nil {
		md.WriteString("## 📜 Certificate Information\n\n")
		if len(results.CertificateInfo.Certificates) > 0 {
			c := results.CertificateInfo.Certificates[0]
			md.WriteString(fmt.Sprintf("- **File:** `%s`\n", c.FileName))
			md.WriteString(fmt.Sprintf("- **Issuer:** %s\n", c.Issuer))
			md.WriteString(fmt.Sprintf("- **Subject:** %s\n", c.Subject))
			md.WriteString(fmt.Sprintf("- **Valid From:** %s\n", c.ValidFrom))
			md.WriteString(fmt.Sprintf("- **Valid To:** %s\n", c.ValidTo))
			if c.IsSelfSigned {
				md.WriteString("- ⚠️ **Self-signed certificate**\n")
			}
			if c.IsExpired {
				md.WriteString("- ❌ **Certificate expired**\n")
			}
		}
		if len(results.CertificateInfo.SecurityNotes) > 0 {
			md.WriteString("\n**Security Notes:**\n")
			for _, n := range results.CertificateInfo.SecurityNotes {
				md.WriteString(fmt.Sprintf("- %s\n", n))
			}
		}
		addGap()
	}

	if len(results.Emails) > 0 {
		md.WriteString(fmt.Sprintf("## 📧 Emails\n\n**Total Found:** %d → [View All](emails.txt)\n\n", len(results.Emails)))
		md.WriteString("**Sample (first 10):**\n\n")
		for i, email := range results.Emails {
			if i >= 10 {
				break
			}
			md.WriteString(fmt.Sprintf("- `%s`\n", email))
		}
		if len(results.Emails) > 10 {
			md.WriteString(fmt.Sprintf("\n*... and %d more in [emails.txt](emails.txt)*\n", len(results.Emails)-10))
		}
		addGap()
	}

	if len(results.Domains) > 0 {
		md.WriteString(fmt.Sprintf("## 🌐 Domains\n\n**Total Found:** %d → [View All](domains.txt)\n\n", len(results.Domains)))
		md.WriteString("**Sample (first 10):**\n\n")
		for i, domain := range results.Domains {
			if i >= 10 {
				break
			}
			md.WriteString(fmt.Sprintf("- `%s`\n", domain))
		}
		if len(results.Domains) > 10 {
			md.WriteString(fmt.Sprintf("\n*... and %d more in [domains.txt](domains.txt)*\n", len(results.Domains)-10))
		}
		addGap()
	}

	if len(allURLs) > 0 {
		md.WriteString(fmt.Sprintf("## 🔗 URLs\n\n**Total Found:** %d → [View All](urls.txt)\n\n", len(allURLs)))
		md.WriteString(fmt.Sprintf("- HTTP: %d\n", len(results.URLs.HTTP)))
		md.WriteString(fmt.Sprintf("- HTTPS: %d\n", len(results.URLs.HTTPS)))
		md.WriteString(fmt.Sprintf("- Other: %d\n", len(results.URLs.FTP)+len(results.URLs.WS)+len(results.URLs.WSS)+len(results.URLs.File)+len(results.URLs.Content)+len(results.URLs.Other)))
		addGap()
	}

	if len(results.APIEndpoints) > 0 {
		md.WriteString(fmt.Sprintf("## 🛠 API Endpoints\n\n**Total Found:** %d → [View All](api_endpoints.txt)\n\n", len(results.APIEndpoints)))
		md.WriteString("**Sample (first 10):**\n\n")
		for i, endpoint := range results.APIEndpoints {
			if i >= 10 {
				break
			}
			md.WriteString(fmt.Sprintf("- `[%s]` %s\n", endpoint.Method, endpoint.URL))
		}
		if len(results.APIEndpoints) > 10 {
			md.WriteString(fmt.Sprintf("\n*... and %d more in [api_endpoints.txt](api_endpoints.txt)*\n", len(results.APIEndpoints)-10))
		}
		addGap()
	}

	if len(results.HardcodedKeys) > 0 {
		md.WriteString(fmt.Sprintf("## 🔑 Hardcoded Keys\n\n**Total Found:** %d → [View All](hardcoded_keys.txt)\n\n", len(results.HardcodedKeys)))
		md.WriteString("⚠️ **Security Risk:** Hardcoded secrets detected!\n\n")
		md.WriteString("**Sample (first 5):**\n\n")
		for i, key := range results.HardcodedKeys {
			if i >= 5 {
				break
			}
			md.WriteString(fmt.Sprintf("- `%s`\n", key))
		}
		if len(results.HardcodedKeys) > 5 {
			md.WriteString(fmt.Sprintf("\n*... and %d more in [hardcoded_keys.txt](hardcoded_keys.txt)*\n", len(results.HardcodedKeys)-5))
		}
		addGap()
	}

	if results.Firebase != nil {
		md.WriteString("## 🔥 Firebase Configuration\n\n")
		md.WriteString(fmt.Sprintf("- **Project ID:** `%s`\n", results.Firebase.ProjectID))
		md.WriteString(fmt.Sprintf("- **Storage Bucket:** `%s`\n", results.Firebase.StorageBucket))
		if results.Firebase.APIKeyMasked != "" {
			md.WriteString(fmt.Sprintf("- **API Key:** `%s`\n", results.Firebase.APIKeyMasked))
		}
		if len(results.Firebase.Endpoints) > 0 {
			md.WriteString("\n**Endpoints:**\n")
			for _, e := range results.Firebase.Endpoints {
				md.WriteString(fmt.Sprintf("- `%s`\n", e))
			}
		}
		addGap()
	}

	if len(results.Services) > 0 {
		md.WriteString(fmt.Sprintf("## ⚙️ Third-Party Services\n\n**Total Detected:** %d → [View All](services.txt)\n\n", len(results.Services)))
		for _, svc := range results.Services {
			md.WriteString(fmt.Sprintf("### %s\n\n", svc.Name))
			if len(svc.Indicators) > 0 {
				md.WriteString("**Indicators:**\n")
				for _, ind := range svc.Indicators {
					md.WriteString(fmt.Sprintf("- %s\n", ind))
				}
			}
			if len(svc.Domains) > 0 {
				md.WriteString("\n**Domains:**\n")
				for _, d := range svc.Domains {
					md.WriteString(fmt.Sprintf("- `%s`\n", d))
				}
			}
			if len(svc.Keys) > 0 {
				md.WriteString("\n**Keys:**\n")
				for _, k := range svc.Keys {
					md.WriteString(fmt.Sprintf("- `%s`\n", k))
				}
			}
			addGap()
		}
	}

	if len(results.Permissions) > 0 {
		md.WriteString(fmt.Sprintf("## 🔒 Permissions\n\n**Total:** %d → [View All](permissions.txt)\n\n", len(results.Permissions)))
		dangerousCount := 0
		for _, perm := range results.Permissions {
			if perm.Dangerous {
				dangerousCount++
			}
		}
		md.WriteString(fmt.Sprintf("- ⚠️ **Dangerous:** %d\n", dangerousCount))
		md.WriteString(fmt.Sprintf("- ✅ **Normal:** %d\n\n", len(results.Permissions)-dangerousCount))

		if dangerousCount > 0 {
			md.WriteString("**Dangerous Permissions:**\n\n")
			count := 0
			for _, perm := range results.Permissions {
				if perm.Dangerous && count < 10 {
					md.WriteString(fmt.Sprintf("- `%s`\n", perm.Name))
					count++
				}
			}
			if dangerousCount > 10 {
				md.WriteString(fmt.Sprintf("\n*... and %d more in [permissions.txt](permissions.txt)*\n", dangerousCount-10))
			}
		}
		addGap()
	}

	if len(results.Packages) > 0 {
		md.WriteString(fmt.Sprintf("## 📦 Flutter Packages\n\n**Total:** %d → [View All](packages.txt)\n\n", len(results.Packages)))
		md.WriteString("**Sample (first 10):**\n\n")
		for i, pkg := range results.Packages {
			if i >= 10 {
				break
			}
			md.WriteString(fmt.Sprintf("- [`%s`](%s) %s\n", pkg.Name, pkg.URL, pkg.Version))
		}
		if len(results.Packages) > 10 {
			md.WriteString(fmt.Sprintf("\n*... and %d more in [packages.txt](packages.txt)*\n", len(results.Packages)-10))
		}
		addGap()
	}

	if len(allAssets) > 0 {
		md.WriteString(fmt.Sprintf("## 📁 Assets\n\n**Total Files:** %d → [View Folder](assets/)\n\n", len(allAssets)))

		extCounts := make(map[string]int)
		for _, file := range allAssets {
			ext := strings.TrimPrefix(strings.ToLower(filepath.Ext(file.Name)), ".")
			if ext == "" {
				ext = "no_extension"
			}
			extCounts[ext]++
		}

		md.WriteString("**Files by Extension:**\n\n")
		for ext, count := range extCounts {
			md.WriteString(fmt.Sprintf("- [`%s`](assets/%s/) - %d files\n", ext, ext, count))
		}
		addGap()
	}

	if results.DecompiledDirPath != "" {
		md.WriteString("## 📦 Decompiled APK\n\n")
		md.WriteString("The full decompiled APK contents are available in the [`decompiled/`](decompiled/) folder.\n\n")
		md.WriteString("This includes:\n")
		md.WriteString("- Decompiled Java/Smali source code\n")
		md.WriteString("- AndroidManifest.xml\n")
		md.WriteString("- Resources (XML layouts, drawables, values)\n")
		md.WriteString("- Native libraries (.so files)\n")
		md.WriteString("- Assets and raw files\n")
		md.WriteString("- META-INF signing information\n\n")
		addGap()
	}

	md.WriteString("---\n\n")
	md.WriteString("## 📊 Full Analysis\n\n")
	md.WriteString("For complete detailed analysis data, see [analysis.json](analysis.json)\n\n")
	md.WriteString("*Generated by FlutterGuard CLI*\n")

	return md.String()
}
