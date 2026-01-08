#!/usr/bin/env bash
set -e

REPO="flutterguard/flutterguard-cli"
BINARY_NAME="flutterguard-cli"
INSTALL_DIR="/usr/local/bin"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Detect OS and architecture
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

echo "🔍 Detecting system..."
echo "   OS: $OS"
echo "   Architecture: $ARCH"

# Map architecture to Go arch naming
case "$ARCH" in
    x86_64) ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    armv7l) ARCH="arm" ;;
    i386|i686) ARCH="386" ;;
    *) 
        echo -e "${RED}❌ Unsupported architecture: $ARCH${NC}"
        echo "   Supported: x86_64, aarch64, arm64, armv7l, i386, i686"
        exit 1
        ;;
esac

# Check OS support
case "$OS" in
    linux|darwin) ;;
    mingw*|msys*|cygwin*) 
        echo -e "${RED}❌ Please use install.ps1 for Windows${NC}"
        echo "   Run: irm https://raw.githubusercontent.com/$REPO/main/install.ps1 | iex"
        exit 1
        ;;
    *) 
        echo -e "${RED}❌ Unsupported OS: $OS${NC}"
        echo "   Supported: Linux, macOS"
        exit 1
        ;;
esac

# Construct download URL
DOWNLOAD_URL="https://github.com/$REPO/releases/latest/download/${BINARY_NAME}-${OS}-${ARCH}"

echo ""
echo "📥 Downloading FlutterGuard CLI..."
echo "   From: $DOWNLOAD_URL"

# Download with progress
if command -v curl &> /dev/null; then
    curl -fL --progress-bar "$DOWNLOAD_URL" -o "$BINARY_NAME" || {
        echo -e "${RED}❌ Download failed. Please check:${NC}"
        echo "   1. Your internet connection"
        echo "   2. The release exists: https://github.com/$REPO/releases/latest"
        exit 1
    }
elif command -v wget &> /dev/null; then
    wget --show-progress -O "$BINARY_NAME" "$DOWNLOAD_URL" || {
        echo -e "${RED}❌ Download failed. Please check:${NC}"
        echo "   1. Your internet connection"
        echo "   2. The release exists: https://github.com/$REPO/releases/latest"
        exit 1
    }
else
    echo -e "${RED}❌ Neither curl nor wget found. Please install one of them.${NC}"
    exit 1
fi

# Make executable
chmod +x "$BINARY_NAME"

echo ""
echo "📦 Installing..."

# Try to install to /usr/local/bin
if [ -w "$INSTALL_DIR" ]; then
    mv "$BINARY_NAME" "$INSTALL_DIR/"
    echo -e "${GREEN}✅ Installed to $INSTALL_DIR/$BINARY_NAME${NC}"
elif command -v sudo &> /dev/null; then
    echo "   (requires sudo for $INSTALL_DIR)"
    sudo mv "$BINARY_NAME" "$INSTALL_DIR/" || {
        echo -e "${YELLOW}⚠️  Failed to install to $INSTALL_DIR${NC}"
        echo "   Binary is in current directory: ./$BINARY_NAME"
        echo "   To install manually:"
        echo "   sudo mv $BINARY_NAME $INSTALL_DIR/"
        exit 0
    }
    echo -e "${GREEN}✅ Installed to $INSTALL_DIR/$BINARY_NAME${NC}"
else
    echo -e "${YELLOW}⚠️  Cannot write to $INSTALL_DIR and sudo not available${NC}"
    echo "   Binary downloaded to: ./$BINARY_NAME"
    echo "   To install manually:"
    echo "   sudo mv $BINARY_NAME $INSTALL_DIR/"
    exit 0
fi

# Verify installation
echo ""
echo "🎉 Installation complete!"
echo ""

if command -v "$BINARY_NAME" &> /dev/null; then
    VERSION=$("$BINARY_NAME" --version 2>&1 || echo "unknown")
    echo -e "${GREEN}✓${NC} Version: $VERSION"
    echo ""
    echo "Try it out:"
    echo "  $BINARY_NAME --help"
    echo "  $BINARY_NAME --apk your-app.apk"
else
    echo -e "${YELLOW}⚠️  Binary installed but not in PATH${NC}"
    echo "   You may need to restart your terminal or add $INSTALL_DIR to PATH"
fi
