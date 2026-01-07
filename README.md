# FlutterGuard CLI

A fully local command-line tool to scan Android APKs for embedded secrets, endpoints, packages, permissions, certificates, and common security misconfigurations. Produces the same structured report used by Flutter Spy, without any server calls.

## Features

- Offline analysis: optional `-no-network` disables DNS lookups and host checks
- Multiple decompilation strategies: fast ZIP extraction and JADX fallback
- AAPT2 metadata (package info, permissions, icons, SDK levels)
- Certificate analysis via `openssl`
- Extraction of emails, domains, URLs, IPs, endpoints, request headers
- Firebase config hints, third-party services, CDN detection
- Flutter packages and app metadata
- JSON or text report output

## Installation

Build the `flutterguard-cli` binary:

```bash
# From repository root
mkdir -p build
go build -o build/flutterguard-cli

# Verify
./build/flutterguard-cli --help
```

Requirements:

- Go 1.21+
- Optional: `jadx` for Java source decompilation
- Optional: `aapt2` for rich APK metadata
- Optional: `openssl` for certificate inspection

If these tools are missing, the CLI will still run with available strategies.

## Usage

```bash
# Basic JSON report to stdout
./build/flutterguard-cli --apk /path/to/app.apk

# Text report (human-readable)
./build/flutterguard-cli --apk /path/to/app.apk --format text

# Save report to file
./build/flutterguard-cli --apk /path/to/app.apk --output report.json

# Use a custom JADX path and increase timeout
./build/flutterguard-cli --apk /path/to/app.apk --jadx /usr/local/bin/jadx --jadx-timeout 45

# Strict offline mode (no DNS checks)
./build/flutterguard-cli --apk /path/to/app.apk --no-network
```

### Flags

- `--apk`: Path to APK file (required)
- `--format`: `json` or `text` (default: `json`)
- `--output`: Output file path (default: stdout)
- `--jadx`: Path to `jadx` executable (default: `jadx` in PATH)
- `--jadx-timeout`: Timeout for `jadx` in minutes (default: 30)
- `--no-network`: Disable DNS/host verification for true offline runs
- `--verbose`: Show progress and timing details
- `--version`: Show CLI version
- `--help`: Show usage help

## Reports

- JSON: Complete structured data suitable for downstream tooling
- Text: Concise, readable summary of key findings

Reports can be saved under `export/reports/` or any custom path via `-output`.

## Notes on Offline Mode

- When `-no-network` is enabled, validators skip DNS lookups and reachability checks. This improves privacy and makes operation fully offline, but may include domains/URLs that would otherwise be filtered.

## Project Structure

- `main.go`: CLI entrypoint and I/O
- `models/models.go`: Shared data models for results
- `analyzer/*`: Local analyzer with decompilation, extraction, validation

## Troubleshooting

- If `jadx` is not found, CLI still attempts ZIP-based extraction for Flutter apps
- If `aapt2` or `openssl` are missing, related metadata will be limited
- Use `-verbose` for detailed progress messages

## License

See the root `LICENSE` file.
