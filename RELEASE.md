# Release Process

This document explains how to create and release new versions of FlutterGuard CLI.

## Creating a Release

### 1. Update Version

Update the version constant in `cmd/root.go`:

```go
const Version = "1.1.0"  // Update this
```

### 2. Update CHANGELOG (Optional but recommended)

Create or update CHANGELOG.md with new features, fixes, and improvements.

### 3. Commit Changes

```bash
git add cmd/root.go CHANGELOG.md
git commit -m "Release v1.1.0"
```

### 4. Create Git Tag

```bash
git tag -a v1.1.0 -m "Release FlutterGuard CLI v1.1.0"
git push origin main
git push origin v1.1.0
```

### What Happens Next

When you push a tag starting with `v`, the GitHub Actions workflow automatically:

1. **Builds** the CLI for multiple platforms:

   - Linux (amd64, arm64)
   - macOS (amd64, Apple Silicon/arm64)
   - Windows (amd64)

2. **Creates a GitHub Release** with all built binaries attached

3. **Makes binaries downloadable** from the Releases page

## Supported Platforms

The build workflow creates binaries for:

| Platform | Architecture          | Filename                             |
| -------- | --------------------- | ------------------------------------ |
| Linux    | x86_64 (amd64)        | `flutterguard-cli-linux-amd64`       |
| Linux    | ARM64                 | `flutterguard-cli-linux-arm64`       |
| macOS    | Intel (amd64)         | `flutterguard-cli-darwin-amd64`      |
| macOS    | Apple Silicon (arm64) | `flutterguard-cli-darwin-arm64`      |
| Windows  | x86_64 (amd64)        | `flutterguard-cli-windows-amd64.exe` |

## Troubleshooting

### Build Failed

Check the GitHub Actions logs at: `https://github.com/flutterguard/flutterguard-cli/actions`

### Release Not Created

- Verify the tag was pushed: `git push origin <tag-name>`
- Check that tag starts with `v` (e.g., `v1.0.0`)
- Review workflow logs for errors

### Deprecated artifact action error

If the workflow fails with a message like:

> This request has been automatically failed because it uses a deprecated version of actions/upload-artifact: v3

This usually means the tag you pushed points to an older commit where the workflows still used `actions/upload-artifact@v3`. Fix by retagging the latest commit (which uses `@v4`):

Option A: Create a new tag (recommended)

```bash
git switch main
git pull --ff-only
git tag -a vX.Y.Z -m "Release FlutterGuard CLI vX.Y.Z"
git push origin vX.Y.Z
```

Option B: Move the existing tag to HEAD (force-update)

```bash
# If a GitHub Release exists for the tag, delete it in the UI first
git switch main
git pull --ff-only
git tag -fa vX.Y.Z -m "Release FlutterGuard CLI vX.Y.Z"
git push origin vX.Y.Z --force
```

After pushing, monitor the run at your repository’s Actions page.

## Continuous Integration

Every push to `main` or `develop` branches runs:

- Code formatting checks (`go fmt`)
- Static analysis (`go vet`)
- Unit tests (`go test`)
- Build verification

Failures in CI will prevent merges to main.
