# FlutterGuard CLI 🔍

Ever wanted to peek inside an Android APK and see what's really hiding in there? FlutterGuard CLI does exactly that—it's a command-line tool that digs deep into Android apps to uncover secrets, API endpoints, suspicious permissions, and security issues. Best of all? It runs completely offline on your machine. No cloud, no tracking, just raw analysis.

## What does it do?

FlutterGuard CLI gives you the inside scoop on any Android app:

- 🔑 **Secrets & Credentials** — finds API keys, tokens, and hardcoded passwords
- 🌐 **Network Endpoints** — extracts domains, URLs, API endpoints, and Firebase configs
- 📦 **App Dependencies** — lists Flutter packages and links to pub.dev for more info
- 📋 **Metadata** — pulls package name, version, SDK info, and required permissions
- 🔍 **Third-Party Services** — detects what SDKs, CDNs, and analytics are bundled
- 📜 **Certificates** — analyzes signing certificates and flags self-signed ones
- 📁 **Full Breakdown** — organized assets, resources, and complete decompiled code

**Why you'll love it:**
- 🔒 **Privacy first** — runs offline by default, network features are opt-in
- 📊 **Well-organized output** — generates a clean directory with categorized files and a navigable report
- ⚡ **Smart decompilation** — uses fast ZIP extraction by default, falls back to JADX if needed
- 📈 **Real-time feedback** — shows you exactly where it is in the analysis
- 🎯 **Complete picture** — gives you the decompiled code, assets, and detailed JSON to dig deeper

## Getting Started

### Quickest Way: Download a Release

Head over to [GitHub Releases](https://github.com/flutterguard/flutterguard-cli/releases) and grab the latest binary for your OS:

```bash
# On Linux or macOS:
curl -LO https://github.com/flutterguard/flutterguard-cli/releases/latest/download/flutterguard-cli
chmod +x flutterguard-cli
sudo mv flutterguard-cli /usr/local/bin/

# Test it out
flutterguard-cli --version
```

### Build It Yourself

Already have Go? Clone and build in seconds:

```bash
git clone https://github.com/flutterguard/flutterguard-cli.git
cd flutterguard-cli

# Build it
go build -o build/flutterguard-cli

# Optional: add to PATH
sudo cp build/flutterguard-cli /usr/local/bin/
```

**What you need:**
- Go 1.21+
- That's it! (Everything else is optional)

### Nice-to-Have Tools (Optional)

FlutterGuard works great on its own, but these tools level up the analysis:

- **AAPT2** — gives you richer APK metadata
  - Linux: `sudo apt install aapt`
  - macOS: Install via Android SDK
  
- **JADX** — better Java decompilation (we use ZIP extraction by default)
  - Get it: https://github.com/skylot/jadx/releases
  - Or: `brew install jadx`

- **OpenSSL** — for detailed certificate inspection
  - Usually already on your system

## How to Use It

### The Easiest Way

```bash
# Point it at an APK and watch it work
flutterguard-cli --apk app.apk --outDir ./results --verbose
```

That's it! It'll create a nice folder called `results/com.example.app/` with everything organized and ready to explore.

### Want Different Output?

```bash
# Just get JSON you can pipe around
flutterguard-cli --apk app.apk --format json

# Or a quick text summary
flutterguard-cli --apk app.apk --format text

# Output to a specific folder
flutterguard-cli --apk app.apk --outDir ~/my-analysis
```

### Privacy-Focused by Default

By default, FlutterGuard stays offline—no DNS lookups, no HTTP requests. If you want it to validate domains and check pub.dev for more info about dependencies:

```bash
flutterguard-cli --apk app.apk --outDir ./results --enable-network-and-dns-checks
```

### All Available Options

| Flag | What it does | Default |
|------|------------|---------|
| `--apk` | The APK file to analyze **(required)** | — |
| `--outDir` | Where to save the results folder | stdout |
| `--format` | Output style: `json` or `text` | `json` |
| `--verbose` | Show progress as it runs | off |
| `--enable-network-and-dns-checks` | Enable online features | off |
| `--version` | Show version number | — |
| `--help` | Show all options | — |

## What You Get

When you run with `--outDir`, FlutterGuard creates a beautifully organized folder:

```
results/
└── com.example.app/
    ├── summary.md               ← Start here! Human-readable report with links
    ├── analysis.json            ← Full structured data for scripts/tools
    ├── emails.txt               ← All email addresses found
    ├── domains.txt              ← Domain names and hosts
    ├── urls.txt                 ← Complete list of URLs
    ├── api_endpoints.txt        ← API calls with HTTP methods
    ├── packages.txt             ← Flutter packages + pub.dev links
    ├── permissions.txt          ← Android permissions (⚠️ marks dangerous ones)
    ├── services.txt             ← Third-party SDKs and services
    ├── hardcoded_keys.txt       ← Potential secrets and API keys
    ├── assets/                  ← App resources organized by file type
    │   ├── json/
    │   ├── png/
    │   ├── xml/
    │   ├── ttf/
    │   └── ...
    └── decompiled/              ← Complete APK contents
        ├── AndroidManifest.xml
        ├── classes.dex          ← Compiled Java code
        ├── lib/                 ← Native .so libraries
        ├── res/                 ← App resources
        ├── assets/              ← Embedded files
        └── META-INF/            ← Signing certificates
```

**Pro tip:** Open `summary.md` in any markdown viewer or on GitHub—it has a table of contents with clickable links to everything else!

## Inside the Code

### Folder Layout

```
flutterguard-cli/
├── main.go                  # Entry point (just calls the CLI)
├── cmd/                     # Command-line magic
│   ├── root.go             # Defines all the flags
│   ├── analyze.go          # Orchestrates the actual analysis
│   ├── output.go           # Saves results to folders
│   ├── output_text.go      # Text report generator
│   └── output_markdown.go  # Markdown report generator
├── analyzer/               # Where the real work happens
│   ├── analyzer.go         # Main analysis pipeline
│   ├── config.go           # Configuration options
│   ├── progress.go         # Progress event types
│   ├── decompiler.go       # Smart decompilation strategy picker
│   ├── jadx_decompiler.go  # JADX integration
│   ├── apk_zip_decompiler.go  # Fast ZIP extraction
│   ├── aapt2_extractor.go  # APK metadata via AAPT2
│   ├── certificate_analyzer.go  # Certificate inspection
│   ├── patterns.go         # Regex patterns for finding stuff
│   ├── validators.go       # Email/URL/domain checkers
│   ├── pubdev.go           # Talks to pub.dev API
│   ├── secrets_detector.go # Finds API keys and secrets
│   ├── assets_scanner.go   # Finds embedded files
│   ├── file_types.go       # File analysis
│   └── ...
└── models/
    └── models.go           # Data structure definitions
```

### How It Works (High Level)

1. **CLI Layer** — parses your flags and arguments (via Cobra)
2. **Analysis Layer** — does the heavy lifting (decompiles, extracts, validates)
3. **Data Layer** — passes results around using structured types
4. **Output Layer** — saves to disk in nice organized folders

### Design Philosophy

- **Offline first** — privacy matters, so everything runs local by default
- **Graceful degradation** — missing tools? No problem, use what you've got
- **Progress visibility** — people like to know what's happening (shows 10%, 20%... 100%)
- **Smart defaults** — organized folder structure, markdown reports, everything categorized
- **Package-based naming** — output folder named after the actual app package

## Want to Help?

We'd love your contributions! Whether it's a bug fix, new feature, or just improving docs.

### Getting Started as a Contributor

```bash
# 1. Fork the repo on GitHub
# 2. Clone your fork
git clone https://github.com/YOUR_USERNAME/flutterguard-cli.git
cd flutterguard-cli

# 3. Grab dependencies
go mod download

# 4. Build it
go build -o build/flutterguard-cli

# 5. Make your changes and test
go test ./...
```

### What We Need Help With

- 🔍 **New Detection Patterns** — find more secrets and suspicious code
- 🛠️ **Tool Support** — integrate other decompilers or analyzers
- 📊 **Report Formats** — HTML, PDF, CSV exports
- 🐛 **Bug Fixes** — found a problem? Fix it!
- 📚 **Docs & Examples** — tutorials, use cases, write-ups
- 🌍 **Internationalization** — help translate

### How to Contribute

1. Fork and create a feature branch
2. Make your changes with clear, descriptive commit messages
3. Add tests for new features
4. Update docs if needed
5. Run `go test ./...` to make sure everything works
6. Submit a pull request with details about what you changed

### Our Code Style

- Follow standard Go style (`gofmt`, `go vet`)
- Use clear, meaningful names for functions and variables
- Comment exported functions and tricky logic
- Keep functions small and focused on one thing

### Found a Bug?

Open an [issue](https://github.com/flutterguard/flutterguard-cli/issues) and tell us:
- What you were trying to do
- What went wrong
- What you expected to happen
- Your OS, Go version, and any other relevant details

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [JADX](https://github.com/skylot/jadx) - Dex to Java decompiler
- [Cobra](https://github.com/spf13/cobra) - CLI framework
- Android SDK Tools - APK metadata extraction

---

**Built with ❤️ for the Flutter and Android security community**
