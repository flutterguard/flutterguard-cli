#!/usr/bin/env pwsh
$ErrorActionPreference = 'Stop'

$repo = "flutterguard/flutterguard-cli"
$binaryName = "flutterguard-cli.exe"
$installDir = "$env:LOCALAPPDATA\Programs\FlutterGuard"

Write-Host ""
Write-Host "🔍 Detecting system..." -ForegroundColor Cyan
Write-Host "   OS: Windows" -ForegroundColor Gray
Write-Host "   Architecture: $env:PROCESSOR_ARCHITECTURE" -ForegroundColor Gray

# Determine architecture
$arch = "amd64"
if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") {
    $arch = "arm64"
}

$downloadUrl = "https://github.com/$repo/releases/latest/download/flutterguard-cli-windows-$arch.exe"

Write-Host ""
Write-Host "📥 Downloading FlutterGuard CLI..." -ForegroundColor Cyan
Write-Host "   From: $downloadUrl" -ForegroundColor Gray

try {
    # Download with progress
    $ProgressPreference = 'SilentlyContinue'  # Faster downloads
    Invoke-WebRequest -Uri $downloadUrl -OutFile $binaryName -UseBasicParsing
    $ProgressPreference = 'Continue'
    Write-Host "   ✓ Downloaded successfully" -ForegroundColor Green
} catch {
    Write-Host ""
    Write-Host "❌ Download failed: $_" -ForegroundColor Red
    Write-Host "   Please check:" -ForegroundColor Yellow
    Write-Host "   1. Your internet connection" -ForegroundColor Yellow
    Write-Host "   2. The release exists: https://github.com/$repo/releases/latest" -ForegroundColor Yellow
    exit 1
}

Write-Host ""
Write-Host "📦 Installing..." -ForegroundColor Cyan

# Create installation directory
try {
    New-Item -ItemType Directory -Force -Path $installDir | Out-Null
    Move-Item -Force $binaryName "$installDir\$binaryName"
    Write-Host "   ✓ Installed to $installDir" -ForegroundColor Green
} catch {
    Write-Host "   ⚠️  Failed to move to $installDir" -ForegroundColor Yellow
    Write-Host "   Binary is in current directory: .\$binaryName" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "To install manually:" -ForegroundColor Yellow
    Write-Host "   Move-Item $binaryName $installDir\" -ForegroundColor Gray
    exit 0
}

# Add to PATH if not already there
Write-Host "   Updating PATH..." -ForegroundColor Gray
try {
    $currentPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if ($currentPath -notlike "*$installDir*") {
        [Environment]::SetEnvironmentVariable("Path", "$currentPath;$installDir", "User")
        Write-Host "   ✓ Added to PATH (restart terminal to use)" -ForegroundColor Green
        $env:Path = "$env:Path;$installDir"  # Update current session
    } else {
        Write-Host "   ✓ Already in PATH" -ForegroundColor Green
    }
} catch {
    Write-Host "   ⚠️  Could not update PATH automatically" -ForegroundColor Yellow
    Write-Host "   Please add manually: $installDir" -ForegroundColor Yellow
}

# Verify installation
Write-Host ""
Write-Host "🎉 Installation complete!" -ForegroundColor Green
Write-Host ""

try {
    $version = & "$installDir\$binaryName" --version 2>&1
    Write-Host "✓ Version: $version" -ForegroundColor Green
} catch {
    Write-Host "✓ Installed to: $installDir\$binaryName" -ForegroundColor Green
}

Write-Host ""
Write-Host "Try it out:" -ForegroundColor Cyan
Write-Host "  flutterguard-cli --help" -ForegroundColor Gray
Write-Host "  flutterguard-cli --apk your-app.apk" -ForegroundColor Gray
Write-Host ""
Write-Host "Note: If command not found, restart your terminal or run:" -ForegroundColor Yellow
Write-Host "  `$env:Path = `"$env:Path;$installDir`"" -ForegroundColor Gray
