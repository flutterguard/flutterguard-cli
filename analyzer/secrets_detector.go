package analyzer

import (
    "net/url"
    "regexp"
    "strings"
)


func (a *Analyzer) detectHardcodedKeys(content string) []string {
    patterns := []string{
        // Generic secrets with common keywords
        `(?i)(api[_-]?key|apikey|secret|token|auth[_-]?token|bearer)["'\s:=]{1,4}([A-Za-z0-9_\-]{16,})`,
        // Stripe live keys
        `(?i)(sk_live|rk_live|pk_live)[A-Za-z0-9_\-]{16,}`,
        // AWS access key IDs
        `AKIA[0-9A-Z]{16}`,
        // AWS session access key IDs
        `ASIA[0-9A-Z]{16}`,
        // AWS secret access keys (40 base64-ish chars)
        `(?i)aws(.{0,12})?(secret|access)["'\s:=]{1,6}([A-Za-z0-9/+=]{40})`,
        // AWS session tokens (long base64-ish)
        `(?i)aws(.{0,12})?(session|temp)["'\s:=]{1,6}([A-Za-z0-9/+=]{40,})`,
        // Google API key (client-side)
        `AIza[0-9A-Za-z\-_]{35}`,
        // Google OAuth client ID
        `[0-9]{12}-[a-z0-9\-]{32}\.apps\.googleusercontent\.com`,
        // Google service account private key IDs
        `"private_key_id"\s*:\s*"[a-f0-9]{40}"`,
        // GitHub personal access tokens
        `ghp_[A-Za-z0-9]{36}`,
        // GitHub fine-grained tokens
        `github_pat_[A-Za-z0-9_]{22,}`,
        // Slack legacy and modern tokens
        `xox[baprs]-[0-9]{8,}-[0-9]{8,}-[a-zA-Z0-9]{24,}`,
        `xoxe?-[A-Za-z0-9\-]{10,}-[A-Za-z0-9\-]{10,}-[A-Za-z0-9\-]{24,}`,
        // Slack incoming webhooks
        `https://hooks\.slack\.com/services/[A-Za-z0-9+/]{6,}/[A-Za-z0-9+/]{6,}/[A-Za-z0-9+/]{24,}`,
        // Discord webhooks
        `https://discord\.com/api/webhooks/\d{17,20}/[A-Za-z0-9_-]{20,}`,
        // Telegram bot tokens
        `\d{8,10}:AA[\w-]{33}`,
        // Twilio Account SID
        `AC[a-f0-9]{32}`,
        // Twilio auth tokens (scoped by keyword to cut false positives)
        `(?i)twilio["'\s:=]{1,6}([a-f0-9]{32})`,
        // Mailgun private key
        `key-[0-9a-zA-Z]{32}`,
        // SendGrid API key
        `SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}`,
        // Azure storage connection strings
        `DefaultEndpointsProtocol=https;AccountName=[A-Za-z0-9]+;AccountKey=[A-Za-z0-9+/=]{40,};EndpointSuffix=core\.windows\.net`,
        // Azure SAS tokens
        `sig=[A-Za-z0-9%]{20,}&se=\d{4}-\d{2}-\d{2}`,
        // Mapbox public/secret tokens
        `pk\.[A-Za-z0-9]{60,}`,
        // reCAPTCHA keys
        `(?i)recaptcha["'\s:=]{1,6}([0-9A-Za-z_-]{30,})`,
        // JWT-like bearer blobs
        `eyJ[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{10,}`,
        // Sentry DSN
        `https://[a-z0-9]+@[a-z0-9.-]+/\d+`,
        // PEM private keys (RSA/EC/OPENSSH)
        `-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]+?-----END (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----`,
    }

    var results []string
    for _, p := range patterns {
        re := regexp.MustCompile(p)
        matches := re.FindAllString(content, -1)
        if matches != nil {
            results = append(results, matches...)
        }
    }
    return results
}

func (a *Analyzer) detectInstallSources(content string) []string {
    clues := map[string]string{
        // Official Play Store signals
        "com.android.vending":         "Play Store installer detected",
        "market://details":            "Play Store deep link found",
        "play.google.com/store":       "Play Store URL found",
        "com.google.android.feedback": "Play Store feedback channel referenced",

        // Third-party and OEM stores
        "com.amazon.venezia":               "Amazon Appstore detected",
        "com.amazon.appmanager":            "Amazon Appstore manager detected",
        "com.sec.android.app.samsungapps":  "Samsung Galaxy Store detected",
        "com.xiaomi.market":                "Xiaomi/MIUI store detected",
        "com.huawei.appmarket":             "Huawei AppGallery detected",
        "com.oppo.market":                  "OPPO market detected",
        "com.vivo.appstore":                "Vivo app store detected",
        "com.tencent.android.qqdownloader": "Tencent MyApp store detected",

        // Sideload and installer references
        "INSTALL_NON_MARKET_APPS":    "Sideload permission referenced",
        "unknown sources":            "Unknown sources mention",
        "packageinstaller":           "Package installer reference",
        "adb_install":                "ADB install hint",
        "adb shell pm install":       "ADB shell install command",
        "SESSION_VERIFIER_INSTALLER": "PackageInstaller session verifier mention",

        // Web APK / PWA installs
        "webapk":               "WebAPK/PWA install marker",
        "trusted web activity": "Trusted Web Activity hint",

        // Enterprise / MDM distribution
        "mdm":                  "Mobile Device Management hint",
        "device owner":         "Device owner profile hint",
        "managed provisioning": "Managed provisioning hint",
        "work profile":         "Work profile / enterprise deployment",
    }

    var results []string
    lower := strings.ToLower(content)
    for k, v := range clues {
        if strings.Contains(lower, strings.ToLower(k)) {
            results = append(results, v)
        }
    }

    return uniqueStringsLocal(results)
}

func (a *Analyzer) detectEnvironmentHints(content string) []string {
    clues := []string{"prod", "production", "staging", "stage", "dev", "qa", "sandbox"}
    lower := strings.ToLower(content)
    var hits []string
    for _, c := range clues {
        if strings.Contains(lower, c+".") || strings.Contains(lower, c+"-") || strings.Contains(lower, "/"+c) {
            hits = append(hits, c)
        }
    }
    return hits
}

func (a *Analyzer) detectCDNs(content string, urls map[string][]string) []string {
    providers := []string{"cloudflare", "fastly", "akamai", "cloudfront", "cdn.", "jsdelivr", "unpkg", "gstatic", "cdn.jsdelivr.net", "cdn.cloudflare.com"}
    var results []string
    seen := make(map[string]struct{})

    isProviderHost := func(host string) bool {
        lhost := strings.ToLower(host)
        for _, p := range providers {
            if strings.Contains(lhost, p) {
                return true
            }
        }
        return false
    }

    addIfValid := func(candidate string) {
        c := strings.Trim(candidate, " \t\r\n\"'(),;<>")
        if c == "" {
            return
        }

        parsed, err := url.Parse(c)
        if err != nil || parsed.Host == "" {
            parsed, err = url.Parse("https://" + c)
            if err != nil || parsed.Host == "" {
                return
            }
        }

        if parsed.Scheme == "" {
            parsed.Scheme = "https"
        }

        if parsed.Scheme != "http" && parsed.Scheme != "https" {
            return
        }

        if !isProviderHost(parsed.Host) {
            return
        }

        normalized := parsed.String()
        if _, exists := seen[normalized]; exists {
            return
        }
        seen[normalized] = struct{}{}
        results = append(results, normalized)
    }

    for _, list := range urls {
        for _, u := range list {
            addIfValid(u)
        }
    }

    urlRegex := regexp.MustCompile(`https?://[^\s"'<>]+`)
    for _, match := range urlRegex.FindAllString(content, -1) {
        addIfValid(match)
    }

    return results
}
