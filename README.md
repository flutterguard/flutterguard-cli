# FlutterGuard CLI

FlutterGuard CLI is a static analysis tool for Flutter Android APKs. It extracts security-relevant signals from application binaries and produces a structured report that can be used by engineering, security, compliance, and audit teams.

The tool is designed to be practical in real workflows:
- Local-first analysis
- Deterministic output location and structure
- Optional AI summary generation for risk triage
- Suitable for manual review, CI, and downstream automation

## Table of Contents

1. [What It Analyzes](#what-it-analyzes)
2. [Installation](#installation)
3. [Quick Start](#quick-start)
4. [Command Reference](#command-reference)
5. [AI Remediation and OpenRouter](#ai-remediation-and-openrouter)
6. [Output Structure and Expected Results](#output-structure-and-expected-results)
7. [Common Workflows](#common-workflows)
8. [Error Handling and Troubleshooting](#error-handling-and-troubleshooting)
9. [Development](#development)
10. [Contributing](#contributing)
11. [License](#license)

## What It Analyzes

FlutterGuard performs static APK analysis and reports findings across:

- Application metadata (package name, version, SDK targets)
- Permissions and dangerous permission counts
- URLs, domains, API endpoints, and network behavior hints
- Hardcoded keys/secrets and configuration artifacts
- Third-party packages, services, and SDK privacy impact indicators
- Firebase and platform integration traces
- SQL and local data storage indicators
- Decompilation strategy/attempt metadata
- Extracted files and visual resources for inspection

## Installation

### Option 1: Build From Source

Requirements:
- Go 1.24+
- Git

```bash
git clone https://github.com/flutterguard/flutterguard-cli.git
cd flutterguard-cli
go build -o build/flutterguard-cli .
./build/flutterguard-cli --version
```

### Option 2: Install Script

Linux/macOS:

```bash
curl -sSL https://raw.githubusercontent.com/flutterguard/flutterguard-cli/main/install.sh | bash
```

Windows PowerShell:

```powershell
irm https://raw.githubusercontent.com/flutterguard/flutterguard-cli/main/install.ps1 | iex
```

### Optional External Tools

FlutterGuard works without external tooling, but these can enrich analysis quality:

- `aapt2` for richer APK metadata extraction
- `jadx` for improved decompilation in some cases
- `openssl` for certificate inspection details

## Quick Start

Run analysis for an APK:

```bash
flutterguard-cli --apk app-release.apk --outDir ./results
```

If `--outDir` is omitted, FlutterGuard writes to `./results` by default.

## Command Reference

Basic syntax:

```bash
flutterguard-cli --apk <path-to-apk> [flags]
```

Required flag:
- `--apk`: Path to the APK file to analyze

General flags:
- `--outDir`: Base output directory (default: `results`)
- `--verbose`: Enable verbose execution output
- `--enable-network-and-dns-checks`: Enable network-backed enrichment checks
- `--format`: `json|text` (retained for CLI compatibility; structured report output is generated in all cases)
- `--version`: Print version and exit

AI flags:
- `--ai-remediation`: Enable AI summary generation
- `--ai-provider`: `openai|openrouter|xai|gemini|claude`
- `--ai-key`: API key for selected provider (or `FLUTTERGUARD_AI_KEY`)
- `--ai-baseurl`: Optional custom API base URL
- `--ai-model`: Optional model override

## AI Remediation and OpenRouter

OpenRouter is supported through an OpenAI-compatible API workflow.

### Recommended OpenRouter Run

```bash
export FLUTTERGUARD_AI_KEY="your_openrouter_api_key"

flutterguard-cli \
  --apk "apks/app-arm64-v8a-release.apk" \
  --outDir "./results" \
  --ai-remediation \
  --ai-provider openrouter \
  --ai-baseurl "https://openrouter.ai/api/v1" \
  --ai-model "openai/gpt-4o-mini" \
  --verbose
```

Notes:
- If `--ai-remediation` is enabled but `--ai-key` is missing, the CLI fails fast with a clear error.
- Provider defaults are auto-filled when possible (`--ai-baseurl` and `--ai-model`).
- `gemini` and `claude` are accepted as provider values but currently return a not-implemented error at runtime.

## Output Structure and Expected Results

For each scan, FlutterGuard creates:

`results/{apk_name}/`

Inside that folder:

- `results.json`: Full machine-readable analysis report
- `files/`: Extracted file artifacts (config/content/env/decompiled zip when present)
- `resources/`: Extracted visual and media resources
- `ai_summary.json`: AI summary metadata and text (only when AI remediation is enabled)
- `ai_summary.md`: Human-readable AI summary (only when AI remediation is enabled)

Expected behavior:

1. Each run resets the target `{apk_name}` report folder before writing fresh results.
2. `results.json` is always produced on successful analysis.
3. If AI is enabled and AI provider call fails, fallback summary content is still written, and error context is captured in `ai_summary.json`.

## Common Workflows

### 1. Analyze a Local APK

```bash
flutterguard-cli --apk "apks/app-x86_64-release.apk" --outDir "./results"
```

### 2. Analyze with Network Enrichment

```bash
flutterguard-cli \
  --apk "apks/app-arm64-v8a-release.apk" \
  --outDir "./results" \
  --enable-network-and-dns-checks
```

### 3. Analyze with AI Summary (OpenAI)

```bash
export FLUTTERGUARD_AI_KEY="your_openai_key"

flutterguard-cli \
  --apk "apks/app-arm64-v8a-release.apk" \
  --outDir "./results" \
  --ai-remediation \
  --ai-provider openai \
  --ai-model gpt-4o-mini
```

### 4. Analyze APKs with Special Characters in File Names

```bash
flutterguard-cli \
  --apk "apks/app-arm64-v8a-release(1).apk" \
  --outDir "./results"
```

## Error Handling and Troubleshooting

FlutterGuard surfaces explicit errors for common workflow issues:

- APK path does not exist
- APK path points to a directory instead of a file
- Unsupported `--ai-provider`
- Missing API key when `--ai-remediation` is enabled
- Unsupported or failing AI provider response
- File copy/write failures in output directories

Quick checks:

```bash
flutterguard-cli --version
go test ./...
```

If you suspect stale output, remove the scan folder and rerun:

```bash
rm -rf "results/app-arm64-v8a-release"
flutterguard-cli --apk "apks/app-arm64-v8a-release.apk" --outDir "./results"
```

## Development

Build:

```bash
go build -o build/flutterguard-cli .
```

Test:

```bash
go test ./...
```

Format:

```bash
gofmt -w $(find . -name '*.go' -not -path './vendor/*')
```

## Contributing

Contributions are welcome. Please open an issue or pull request with:

- Clear problem statement
- Reproduction steps
- Proposed fix and rationale
- Test coverage for behavior changes

Before opening a PR:

```bash
go test ./...
go vet ./...
```

## License

MIT License. See [LICENSE](LICENSE).
