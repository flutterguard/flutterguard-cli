# FlutterGuard CLI 🔍

<div align="center">
  <img src="https://flutterguard.dev/logo.png" alt="FlutterGuard Logo" width="200" height="200">
</div>

A powerful command-line tool for analyzing Flutter Android apps to discover security issues, secrets, API endpoints, and more. FlutterGuard runs completely offline on your machine—no cloud services, no tracking, just local analysis.

## What It Does

FlutterGuard CLI analyzes Flutter app APK files and extracts:

- 🔑 **Secrets & API Keys** — Finds hardcoded passwords, tokens, and credentials
- 🌐 **Network Details** — Extracts URLs, domains, API endpoints, and Firebase configs
- 📦 **Dependencies** — Lists all Flutter packages with direct links to pub.dev
- 📋 **App Metadata** — Package name, version, SDK info, and permissions
- 🔍 **Third-Party Services** — Detects bundled SDKs, CDNs, and analytics libraries
- 📜 **Certificate Info** — Analyzes signing certificates and flags self-signed ones
- 📁 **Complete Breakdown** — Organized assets, resources, and full decompiled source code

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

Analyze a Flutter app APK and save organized results to a directory:

```bash
flutterguard-cli --apk app.apk --outDir ./results
```

This creates a folder named after the app's package (e.g., `results/com.example.app/`) containing all findings, assets, and decompiled code.

### Show Progress

Add `--verbose` to see real-time progress updates:

```bash
flutterguard-cli --apk app.apk --outDir ./results --verbose
```

### Output Formats

**JSON format** (default, good for automation):

```bash
flutterguard-cli --apk app.apk --format json
```

**Text format** (human-readable summary):

```bash
flutterguard-cli --apk app.apk --format text
```

**Structured directory** (most comprehensive):

```bash
flutterguard-cli --apk app.apk --outDir ~/my-analysis
```

### Network Features (Opt-In)

By default, FlutterGuard runs completely offline. Enable network features for:

- Domain DNS validation
- pub.dev package information enrichment

```bash
flutterguard-cli --apk app.apk --outDir ./results --enable-network-and-dns-checks
```

## Output Structure

When using `--outDir`, FlutterGuard creates an organized directory structure:

```
results/
└── com.example.app/
    ├── summary.md               ← Start here! Overview with clickable links
    ├── analysis.json            ← Full structured data (JSON)
    ├── emails.txt               ← Email addresses found
    ├── domains.txt              ← Domain names and hosts
    ├── urls.txt                 ← All URLs discovered
    ├── api_endpoints.txt        ← API endpoints with HTTP methods
    ├── packages.txt             ← Flutter packages with pub.dev links
    ├── permissions.txt          ← Android permissions (⚠️ = dangerous)
    ├── services.txt             ← Third-party SDKs detected
    ├── hardcoded_keys.txt       ← Potential secrets and API keys
    ├── assets/                  ← App resources by file type
    │   ├── json/
    │   ├── png/
    │   ├── xml/
    │   ├── ttf/
    │   └── ...
    └── decompiled/              ← Complete APK contents
        ├── AndroidManifest.xml
        ├── classes.dex
        ├── lib/                 ← Native libraries (.so files)
        ├── res/                 ← App resources
        ├── assets/              ← Embedded assets
        └── META-INF/            ← Signing certificates
```

**Tip:** Open `summary.md` in any markdown viewer—it includes a table of contents with links to all findings.

## Why Go instead of Dart?

FlutterGuard is written in Go rather than Dart because:

- **Single Compiled Binary**: Users get a standalone executable with zero dependencies—just download and run, no runtime required.
- **Cross-Platform Distribution**: Go compiles easily to Windows, macOS, and Linux with a single codebase, making it simpler for users across different systems.
- **Performance**: Go offers native compilation speed and efficiency ideal for analyzing large APK files and intensive security scanning operations.
- **CLI Excellence**: Go is purpose-built for command-line tools with strong standard library support for file I/O, process execution, and signal handling.
- **Ecosystem**: Direct access to powerful tools like JADX and aapt2 without the overhead of a UI framework designed for mobile apps.

While Dart excels at building Flutter mobile and web apps, Go is the better choice for a developer tool that needs to be lightweight, fast, and dependency-free.

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

**Built for the Flutter and Android security community**
