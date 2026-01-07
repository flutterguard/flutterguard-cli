# FlutterGuard CLI

A powerful, privacy-focused command-line tool for comprehensive Android APK security analysis. FlutterGuard CLI performs fully local, offline-by-default scanning to extract secrets, endpoints, packages, permissions, certificates, and security misconfigurations—no cloud services required.

## Overview

FlutterGuard CLI is designed for developers, security researchers, and DevSecOps teams who need deep visibility into Android applications. It extracts and analyzes:

- **Secrets & Credentials**: API keys, tokens, hardcoded passwords
- **Network Information**: Domains, URLs, API endpoints, Firebase configs
- **Application Metadata**: Package info, version, SDK levels, permissions
- **Third-Party Services**: Detected SDKs, CDNs, analytics providers
- **Flutter Packages**: Dependencies with version information and pub.dev links
- **Certificates**: Signing information, validity, self-signed detection
- **Assets & Resources**: All embedded files organized by type
- **Decompiled Sources**: Full APK contents for manual inspection

**Key Features:**
- 🔒 **Privacy-first**: Offline by default, network checks require explicit opt-in
- 📊 **Structured Output**: Organized directory with categorized files and Markdown report
- 🚀 **Progress Tracking**: Real-time progress updates with stage-based reporting
- 🔧 **Multiple Strategies**: Fast ZIP extraction with optional JADX decompilation
- 📦 **Complete Artifacts**: Includes decompiled folder, assets, and full analysis data

## Installation

### Option 1: Download from GitHub Releases

Download the latest binary for your platform from the [Releases](https://github.com/flutterguard/flutterguard-cli/releases) page:

```bash
# Linux/macOS
curl -LO https://github.com/flutterguard/flutterguard-cli/releases/latest/download/flutterguard-cli
chmod +x flutterguard-cli
sudo mv flutterguard-cli /usr/local/bin/

# Verify installation
flutterguard-cli --version
```

### Option 2: Build from Source

Requirements:
- Go 1.21 or higher
- Git

```bash
# Clone the repository
git clone https://github.com/flutterguard/flutterguard-cli.git
cd flutterguard-cli

# Build the binary
mkdir -p build
go build -o build/flutterguard-cli

# Optionally, install to PATH
sudo cp build/flutterguard-cli /usr/local/bin/

# Verify
flutterguard-cli --version
```

### Optional Dependencies

While FlutterGuard CLI works standalone, these tools enhance capabilities:

- **AAPT2** (Android Asset Packaging Tool): Rich APK metadata extraction
  - Ubuntu/Debian: `sudo apt install aapt`
  - macOS: Install Android SDK and add `build-tools` to PATH
  
- **JADX**: Advanced Java source decompilation
  - Download: https://github.com/skylot/jadx/releases
  - Or via Homebrew: `brew install jadx`

- **OpenSSL**: Certificate inspection (usually pre-installed on Linux/macOS)

## Usage

### Basic Analysis

```bash
# Analyze APK with structured output (recommended)
flutterguard-cli --apk app.apk --outDir ./output --verbose

# This creates: output/<package-name>/
#   - summary.md (navigable report)
#   - analysis.json (full JSON data)
#   - emails.txt, domains.txt, urls.txt, api_endpoints.txt
#   - packages.txt (Flutter dependencies with pub.dev links)
#   - permissions.txt, services.txt, hardcoded_keys.txt
#   - assets/ (organized by file extension)
#   - decompiled/ (full APK contents)
```

### Output Formats

```bash
# JSON output to stdout (for piping/processing)
flutterguard-cli --apk app.apk --format json

# Text output to stdout (human-readable summary)
flutterguard-cli --apk app.apk --format text

# Structured directory output (most comprehensive)
flutterguard-cli --apk app.apk --outDir ./results
```

### Network Options

```bash
# Default: Offline mode (no DNS/HTTP requests)
flutterguard-cli --apk app.apk --outDir ./output

# Enable network checks for domain validation and pub.dev enrichment
flutterguard-cli --apk app.apk --outDir ./output --enable-network-and-dns-checks
```

### Advanced Options

```bash
# Verbose progress tracking
flutterguard-cli --apk app.apk --outDir ./output --verbose

# Show version
flutterguard-cli --version

# Show help
flutterguard-cli --help
```

### Available Flags

| Flag | Description | Default |
|------|-------------|---------|
| `--apk` | Path to APK file **(required)** | - |
| `--outDir` | Output directory for structured results | (stdout) |
| `--format` | Output format: `json` or `text` | `json` |
| `--verbose` | Show detailed progress and timing | `false` |
| `--enable-network-and-dns-checks` | Enable DNS validation and HTTP requests | `false` |
| `--version` | Show CLI version | - |
| `--help` | Show usage help | - |

## Output Structure

When using `--outDir`, FlutterGuard creates an organized directory:

```
output/
└── com.example.app/
    ├── summary.md                 # Navigable Markdown report with TOC
    ├── analysis.json             # Complete JSON analysis data
    ├── emails.txt                # Extracted email addresses
    ├── domains.txt               # Discovered domains
    ├── urls.txt                  # All URLs (HTTP, HTTPS, WS, etc.)
    ├── api_endpoints.txt         # API endpoints with methods
    ├── packages.txt              # Flutter packages with pub.dev links
    ├── permissions.txt           # Android permissions (dangerous marked)
    ├── services.txt              # Third-party services detected
    ├── hardcoded_keys.txt        # Potential API keys and secrets
    ├── assets/                   # Assets organized by extension
    │   ├── json/                 # JSON files
    │   ├── png/                  # Images
    │   ├── xml/                  # XML configs
    │   └── ...
    └── decompiled/               # Full decompiled APK contents
        ├── AndroidManifest.xml
        ├── classes.dex
        ├── lib/                  # Native libraries (.so files)
        ├── res/                  # Resources
        ├── assets/               # App assets
        └── META-INF/             # Signing info
```

## Developer Notes

### Project Structure

```
flutterguard-cli/
├── main.go              # CLI entrypoint
├── cmd/                 # Cobra command implementations
│   ├── root.go         # Root command and flag definitions
│   ├── analyze.go      # Analysis orchestration with progress
│   ├── output.go       # Structured output generation
│   ├── output_text.go  # Text report formatting
│   └── output_markdown.go  # Markdown summary generation
├── analyzer/           # Core analysis logic
│   ├── analyzer.go     # Main analysis pipeline
│   ├── config.go       # Analyzer configuration
│   ├── progress.go     # Progress reporting types
│   ├── decompiler.go   # Multi-strategy decompilation
│   ├── jadx_decompiler.go  # JADX integration
│   ├── apk_zip_decompiler.go  # ZIP extraction
│   ├── aapt2_extractor.go  # AAPT2 metadata
│   ├── certificate_analyzer.go  # Certificate inspection
│   ├── patterns.go     # Regex patterns for extraction
│   ├── validators.go   # Email/URL/domain validation
│   ├── pubdev.go       # pub.dev API client
│   ├── secrets_detector.go  # Secret detection
│   ├── assets_scanner.go  # Asset file discovery
│   ├── file_types.go   # File type analysis
│   └── ...
└── models/
    └── models.go       # Shared data structures
```

### Architecture

1. **CLI Layer** (`cmd/`): Cobra-based command parsing, flag validation, and user interaction
2. **Analysis Layer** (`analyzer/`): Core security analysis with progress reporting
3. **Data Layer** (`models/`): Structured types for analysis results

### Key Design Decisions

- **Offline by Default**: Network features require explicit opt-in for privacy
- **Progress Tracking**: 10-100% progress with stage labels for UX feedback
- **Multi-Strategy Decompilation**: Falls back gracefully when tools unavailable
- **Structured Output**: Organized by category for easy navigation and tooling integration
- **Package Name as Folder**: Output directory named after app package for clarity

### Running Tests

```bash
# Run all tests
go test ./...

# Run with coverage
go test -cover ./...

# Run specific package tests
go test ./analyzer/...
```

### Building for Multiple Platforms

```bash
# Linux (amd64)
GOOS=linux GOARCH=amd64 go build -o build/flutterguard-cli-linux-amd64

# macOS (Apple Silicon)
GOOS=darwin GOARCH=arm64 go build -o build/flutterguard-cli-darwin-arm64

# Windows
GOOS=windows GOARCH=amd64 go build -o build/flutterguard-cli-windows-amd64.exe
```

## Contributing

We welcome contributions! Here's how to get started:

### Setting Up Development Environment

```bash
# Fork and clone
git clone https://github.com/YOUR_USERNAME/flutterguard-cli.git
cd flutterguard-cli

# Install dependencies
go mod download

# Build and test
go build -o build/flutterguard-cli
./build/flutterguard-cli --help
```

### Contribution Guidelines

1. **Fork the repository** and create a feature branch
2. **Write clear commit messages** describing your changes
3. **Add tests** for new functionality
4. **Update documentation** (README, code comments) as needed
5. **Run tests** before submitting: `go test ./...`
6. **Submit a pull request** with a clear description

### Code Style

- Follow standard Go conventions (`gofmt`, `go vet`)
- Use meaningful variable and function names
- Add comments for exported functions and complex logic
- Keep functions focused and modular

### Areas for Contribution

- 🔍 **New Detectors**: Additional security pattern detection
- 🛠️ **Tool Integrations**: Support for more decompilers/analyzers
- 📊 **Output Formats**: New report formats (HTML, PDF, CSV)
- 🌐 **i18n**: Internationalization support
- 📚 **Documentation**: Tutorials, examples, use cases
- 🐛 **Bug Fixes**: Issue resolution and error handling improvements

### Reporting Issues

Found a bug or have a feature request? Please [open an issue](https://github.com/flutterguard/flutterguard-cli/issues) with:

- Clear description of the problem/feature
- Steps to reproduce (for bugs)
- Expected vs actual behavior
- Your environment (OS, Go version, APK details if applicable)

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [JADX](https://github.com/skylot/jadx) - Dex to Java decompiler
- [Cobra](https://github.com/spf13/cobra) - CLI framework
- Android SDK Tools - APK metadata extraction

---

**Built with ❤️ for the Flutter and Android security community**
