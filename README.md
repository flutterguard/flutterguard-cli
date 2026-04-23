# FlutterGuard CLI

**FlutterGuard CLI** is a professional, AI-powered command-line utility for comprehensive security and compliance analysis of Flutter Android applications. Designed for engineering teams, security professionals, and agencies, FlutterGuard delivers actionable, human-quality remediation guidance and compliance insights for every scan finding.

## Key Features

- **AI-Powered Remediation**: Integrates with leading AI providers (OpenAI, Gemini, Claude, xAI, and more) to generate professional, actionable remediation steps and compliance explanations for every security or privacy finding.
- **Comprehensive Static Analysis**: Detects hardcoded secrets, API endpoints, permissions, SDKs, third-party services, and more.
- **Privacy & Compliance Checks**: Flags risks related to GDPR, COPPA, Play Store, and other regulatory requirements, with clear, human-readable explanations.
- **CI/CD Integration**: Ready for automation in pipelines, with structured output and machine-readable formats.
- **Professional Reports**: Generates detailed Markdown and JSON reports suitable for audits, client delivery, and internal review.
- **Offline-First**: All analysis runs locally by default. No data is sent to the cloud unless you explicitly enable AI or network features.

---

## AI Setup and Usage

FlutterGuard CLI supports multiple AI providers for remediation and compliance guidance. You can configure the AI engine via environment variables or CLI flags.

### Supported Providers

- OpenAI
- Google Gemini
- Anthropic Claude
- xAI
- OpenRouter

### Configuration

Set the following environment variables or use equivalent CLI flags:

- `FLUTTERGUARD_AI_ENABLED=1` — Enable AI-powered remediation
- `FLUTTERGUARD_AI_PROVIDER=openai|gemini|claude|xai|openrouter` — Select provider
- `FLUTTERGUARD_AI_KEY=...` — API key for the selected provider
- `FLUTTERGUARD_AI_BASEURL=...` — (Optional) Custom API endpoint

**Example:**

```bash
export FLUTTERGUARD_AI_ENABLED=1
export FLUTTERGUARD_AI_PROVIDER=openai
export FLUTTERGUARD_AI_KEY=sk-...
flutterguard-cli --apk app.apk --outDir ./results --enable-ai-remediation
```

When enabled, all findings in the report will include a dedicated "Remediation Guidance" section with professional, human-like explanations and actionable steps.

---

## What FlutterGuard CLI Analyzes

- **Secrets & API Keys**: Detects hardcoded credentials and sensitive tokens
- **Network & API Endpoints**: Extracts all URLs, domains, and backend endpoints
- **Dependencies**: Lists all Flutter/Dart packages and third-party SDKs
- **App Metadata**: Reports package name, version, SDK targets, and permissions
- **Third-Party Services**: Identifies analytics, ad networks, and bundled SDKs
- **Certificate Information**: Analyzes signing certificates for trust and compliance
- **Assets & Resources**: Catalogs all embedded files, assets, and resources
- **Decompiled Source**: Optionally provides full decompiled APK contents for audit

## Installation

...existing code...

## Installation

### Quick Install (Recommended)

**One-line install for Linux/macOS:**

```bash
curl -sSL https://raw.githubusercontent.com/flutterguard/flutterguard-cli/main/install.sh | bash
```

**One-line install for Windows (PowerShell):**

```powershell
irm https://raw.githubusercontent.com/flutterguard/flutterguard-cli/main/install.ps1 | iex
```

The script will automatically detect your OS/architecture, download the latest release, and install it to your PATH.

---

### Manual Installation

<details>
<summary><b>Option 1: Download Pre-Built Binary</b></summary>

**Step 1:** Download from [Releases](https://github.com/flutterguard/flutterguard-cli/releases/latest):

| Platform              | Download Link                                                                                                                                      |
| --------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| Linux (x64)           | [flutterguard-cli-linux-amd64](https://github.com/flutterguard/flutterguard-cli/releases/latest/download/flutterguard-cli-linux-amd64)             |
| Linux (ARM64)         | [flutterguard-cli-linux-arm64](https://github.com/flutterguard/flutterguard-cli/releases/latest/download/flutterguard-cli-linux-arm64)             |
| macOS (Intel)         | [flutterguard-cli-darwin-amd64](https://github.com/flutterguard/flutterguard-cli/releases/latest/download/flutterguard-cli-darwin-amd64)           |
| macOS (Apple Silicon) | [flutterguard-cli-darwin-arm64](https://github.com/flutterguard/flutterguard-cli/releases/latest/download/flutterguard-cli-darwin-arm64)           |
| Windows (x64)         | [flutterguard-cli-windows-amd64.exe](https://github.com/flutterguard/flutterguard-cli/releases/latest/download/flutterguard-cli-windows-amd64.exe) |

**Step 2:** Install it on your system:

**Linux/macOS:**

```bash
# Make executable
chmod +x flutterguard-cli-*

# Install to PATH
sudo mv flutterguard-cli-* /usr/local/bin/flutterguard-cli

# Verify
flutterguard-cli --version
```

**Windows:**

1. Rename the downloaded file to `flutterguard-cli.exe`
2. Move it to a directory in your PATH (e.g., `C:\Windows\System32`)
3. Or keep it anywhere and add that directory to your PATH

```powershell
# Verify
flutterguard-cli.exe --version
```

</details>

<details>
<summary><b>Option 2: Build From Source</b></summary>

**Requirements:**

- Go 1.24+ ([Download Go](https://go.dev/dl/))
- Git

**Steps:**

```bash
# Clone the repository
git clone https://github.com/flutterguard/flutterguard-cli.git
cd flutterguard-cli

# Build
go build -o flutterguard-cli

# Install (optional)
sudo mv flutterguard-cli /usr/local/bin/

# Verify
flutterguard-cli --version
```

</details>

<details>
<summary><b>Option 3: Package Managers</b> (Coming Soon)</summary>

We're working on adding support for popular package managers:

- **Homebrew** (macOS/Linux): `brew install flutterguard-cli`
- **Snap** (Linux): `snap install flutterguard-cli`
- **Chocolatey** (Windows): `choco install flutterguard-cli`
- **AUR** (Arch Linux): `yay -S flutterguard-cli`
- **Scoop** (Windows): `scoop install flutterguard-cli`

Stay tuned for updates!

</details>

### Optional Tools for Enhanced Analysis

FlutterGuard works standalone, but these tools provide richer analysis:

- **AAPT2** — Enhanced APK metadata extraction
  - Linux: `sudo apt install aapt`
  - macOS: Included with Android SDK
  - Windows: Download from Android SDK
- **JADX** — Advanced Java decompilation
  - Download: [github.com/skylot/jadx/releases](https://github.com/skylot/jadx/releases)
  - Or via Homebrew: `brew install jadx`
- **OpenSSL** — Detailed certificate inspection (usually pre-installed on Linux/macOS)

## Usage

### Basic Analysis

Run a full security and compliance scan on a Flutter APK:

```bash
flutterguard-cli --apk app.apk --outDir ./results
```

This creates a results directory with all findings, assets, and a professional Markdown report.

### Enabling AI Remediation

Add the `--enable-ai-remediation` flag (or set `FLUTTERGUARD_AI_ENABLED=1`) to include AI-generated remediation and compliance guidance in your reports.

### Output Formats

- `summary.md`: Human-readable, professional Markdown report with remediation guidance
- `analysis.json`: Full structured data for automation and audit
- `*.txt`: Raw lists of emails, domains, endpoints, etc.
- `assets/`: All extracted resources, organized by type
- `decompiled/`: Decompiled APK contents (optional)

### Example Output Structure

...existing code...

## Why FlutterGuard CLI?

- **Professional, Human-Quality Guidance**: All AI-generated remediation is reviewed for clarity, accuracy, and professionalism.
- **No Vendor Lock-In**: Choose your preferred AI provider or run fully offline.
- **Enterprise-Ready**: Designed for security teams, agencies, and regulated environments.
- **Transparent and Auditable**: All findings and AI guidance are saved locally for review and compliance.

FlutterGuard CLI is written in Go for maximum portability, performance, and ease of deployment. No dependencies, no runtime, just a single binary.

## Contributing

Contributions are welcome! Whether it's bug fixes, new features, or documentation improvements.

### Development Setup

```bash
# Fork and clone the repository
git clone https://github.com/YOUR_USERNAME/flutterguard-cli.git
cd flutterguard-cli

# Download dependencies
go mod download

# Build the project
go build -o build/flutterguard-cli

# Run tests
go test ./...
```

### Areas for Contribution

- 🔍 New detection patterns for secrets and suspicious code
- 🛠️ Integration with additional analysis tools
- 📊 New report formats (HTML, PDF, CSV)
- 🐛 Bug fixes and performance improvements
- 📚 Documentation and examples
- 🌍 Internationalization support

### Submitting Changes

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes with clear commit messages
4. Add tests for new functionality
5. Run `go test ./...` and `go vet ./...`
6. Submit a pull request with a clear description

### Code Guidelines

- Follow standard Go formatting (`gofmt`, `go vet`)
- Use descriptive names for functions and variables
- Comment exported functions and complex logic
- Keep functions focused and reasonably sized
- Write tests for new features

### Reporting Issues

Found a bug? [Open an issue](https://github.com/flutterguard/flutterguard-cli/issues) with:

- Description of what you tried to do
- What happened vs. what you expected
- Your OS, Go version, and FlutterGuard version
- Steps to reproduce (if possible)

## License

MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [JADX](https://github.com/skylot/jadx) - Dex to Java decompiler
- [Cobra](https://github.com/spf13/cobra) - CLI framework
- Android SDK Tools - APK analysis utilities

---

_FlutterGuard CLI: Professional AI-powered security and compliance for Flutter applications._
