package analyzer

// RemediationGuide contains guidance for addressing security findings
type RemediationGuide struct {
	Title       string   `json:"title"`
	Risk        string   `json:"risk"`
	Steps       []string `json:"steps"`
	Severity    string   `json:"severity"` // critical, high, medium, low
}

// GetRemediationGuides returns remediation guidance for common security findings
func GetRemediationGuides() map[string]RemediationGuide {
	return map[string]RemediationGuide{
		// Network & Communications
		"hardcoded_keys": {
			Title: "Hardcoded Keys or Secrets",
			Risk: "API keys, tokens, and secrets hardcoded in the app can be extracted and misused to impersonate your app, access backend services, or compromise user data.",
			Steps: []string{
				"Move all keys and secrets to a secure backend server",
				"Use environment-specific configuration (dev, staging, production) managed server-side",
				"Implement a key rotation strategy; never embed secrets in APK",
			},
			Severity: "critical",
		},
		"http_traffic": {
			Title: "Unencrypted HTTP Communication",
			Risk: "Unencrypted HTTP traffic can be intercepted by attackers on the network, exposing sensitive user data, authentication tokens, and communications.",
			Steps: []string{
				"Use HTTPS/TLS for all network requests (require minSdkVersion 24+ for strict cleartext policies)",
				"Implement Certificate Pinning to prevent man-in-the-middle attacks",
				"Test with tools like Burp Suite to verify all traffic is encrypted",
			},
			Severity: "critical",
		},
		"api_endpoints": {
			Title: "Exposed API Endpoints",
			Risk: "Hardcoded API endpoints in the app can be extracted, reverse-engineered, and exploited. Attackers can enumerate endpoints, discover parameters, and perform unauthorized actions.",
			Steps: []string{
				"Fetch API endpoints from a secure configuration server at runtime",
				"Implement API rate limiting and authentication/authorization checks",
				"Use obfuscation tools to complicate reverse engineering of endpoints",
			},
			Severity: "high",
		},
		"firebase_keys": {
			Title: "Firebase Configuration Exposed",
			Risk: "Firebase API keys embedded in the app are by design public, but should never be used with sensitive data. However, exposed Firebase project IDs and keys can be used to enumerate database rules and services.",
			Steps: []string{
				"Review and restrict Firebase Realtime Database rules to authenticated users only",
				"Use Firebase Security Rules to enforce access controls at the database level",
				"Rotate API keys periodically; use Firebase REST API only with proper authentication",
			},
			Severity: "high",
		},
		// Debug & Build
		"debug_mode": {
			Title: "Debug Mode Enabled",
			Risk: "Debug mode in production apps allows attackers to extract sensitive data, modify runtime behavior, and potentially execute arbitrary code via debug bridges.",
			Steps: []string{
				"Disable debuggable=true in AndroidManifest.xml for production builds",
				"Use BuildConfig.DEBUG to conditionally remove sensitive logging",
				"Implement ProGuard/R8 obfuscation for production releases",
			},
			Severity: "critical",
		},
		"missing_proguard": {
			Title: "No Obfuscation Detected",
			Risk: "Without obfuscation, reverse-engineered code is readable, exposing business logic, algorithms, and sensitive operations to attackers.",
			Steps: []string{
				"Enable ProGuard or R8 minification in release builds (build.gradle: minifyEnabled true)",
				"Configure ProGuard rules to keep public APIs while obscuring internal code",
				"Test obfuscated builds to ensure functionality is preserved",
			},
			Severity: "high",
		},
		// Permissions & Privacy
		"dangerous_permissions": {
			Title: "Excessive Dangerous Permissions",
			Risk: "Dangerous permissions like CAMERA, LOCATION, CONTACTS, or SMS give the app broad access to sensitive user data. Over-requesting permissions increases breach impact.",
			Steps: []string{
				"Request only permissions necessary for core functionality",
				"Implement runtime permission requests (Android 6.0+) with user-friendly explanations",
				"Audit and remove unused permissions from AndroidManifest.xml",
			},
			Severity: "high",
		},
		// Data Storage
		"sqlite_databases": {
			Title: "SQLite Databases Without Encryption",
			Risk: "Unencrypted SQLite databases store sensitive user data in plaintext files accessible via file system access, physical access, or backup extraction.",
			Steps: []string{
				"Encrypt SQLite databases using SQLCipher or Room with EncryptedSharedPreferences",
				"Never store passwords, tokens, or PII in plaintext",
				"Use Android Keystore for key management",
			},
			Severity: "high",
		},
		"shared_preferences": {
			Title: "Sensitive Data in SharedPreferences",
			Risk: "SharedPreferences stores data in plaintext XML files readable by any app with file access. User credentials and tokens stored here are easily compromised.",
			Steps: []string{
				"Use EncryptedSharedPreferences (androidx.security library) for all sensitive data",
				"Move session tokens to memory only, never persist to SharedPreferences",
				"Use Android Keystore for encryption key management",
			},
			Severity: "high",
		},
		// Third-party Libraries
		"outdated_dependencies": {
			Title: "Outdated Dependencies with Known Vulnerabilities",
			Risk: "Older library versions often contain publicly disclosed security vulnerabilities. Apps using outdated libraries are vulnerable to known exploits.",
			Steps: []string{
				"Regularly audit dependencies using tools like OWASP Dependency-Check or Snyk",
				"Update dependencies to latest stable versions",
				"Monitor security advisories and apply patches promptly",
			},
			Severity: "high",
		},
		// Code Injection
		"sql_injection": {
			Title: "SQL Injection Risk",
			Risk: "If the app constructs SQL queries by concatenating user input, attackers can inject SQL commands to bypass authentication, extract data, or modify the database.",
			Steps: []string{
				"Always use parameterized queries / prepared statements",
				"Use Room (ORM) or similar frameworks that prevent SQL injection automatically",
				"Never concatenate user input into SQL queries",
			},
			Severity: "critical",
		},
		// Certificate & Security
		"self_signed_certs": {
			Title: "Self-Signed or Untrusted Certificates",
			Risk: "Accepting self-signed or invalid certificates in production defeats HTTPS protection, allowing man-in-the-middle attacks to intercept all communications.",
			Steps: []string{
				"Only accept certificates from trusted Certificate Authorities",
				"Use Certificate Pinning to detect certificate substitution attacks",
				"Implement proper certificate validation in all HTTP clients",
			},
			Severity: "critical",
		},
		// Default values
		"default": {
			Title: "Security Finding",
			Risk: "This finding indicates a potential security concern that may require review.",
			Steps: []string{
				"Review the specific details of this finding",
				"Assess the risk in your app's context",
				"Implement appropriate mitigations based on the finding type",
			},
			Severity: "medium",
		},
	}
}

// GetRemediationGuide returns remediation guidance for a specific finding type
func GetRemediationGuide(findingType string) RemediationGuide {
	guides := GetRemediationGuides()
	if guide, ok := guides[findingType]; ok {
		return guide
	}
	return guides["default"]
}
