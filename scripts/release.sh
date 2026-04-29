#!/bin/bash
# release.sh — Automated release script for SD-WAN Triage Tool
#
# Usage: ./scripts/release.sh [version]
# Example: ./scripts/release.sh 6.0.0
#
# This script:
# 1. Runs tests
# 2. Builds the frontend
# 3. Cross-compiles for all platforms
# 4. Creates release archives
# 5. Publishes to GitHub (optional)

set -e

# ─── Configuration ─────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
VERSION="${1:-6.0.0}"
BUILD_DIR="$PROJECT_ROOT/build"
FRONTEND_DIR="$PROJECT_ROOT/web/frontend"
DIST_DIR="$PROJECT_ROOT/cmd/sdwan-triage/dist"
BINARY_NAME="sdwan-triage"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# ─── Helper Functions ──────────────────────────────────────────────
log_info() {
    echo -e "${BLUE}ℹ${NC} $1"
}

log_success() {
    echo -e "${GREEN}✓${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

log_error() {
    echo -e "${RED}✗${NC} $1"
}

log_step() {
    echo ""
    echo -e "${CYAN}══════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  $1${NC}"
    echo -e "${CYAN}══════════════════════════════════════════════════${NC}"
}

check_command() {
    if ! command -v "$1" &> /dev/null; then
        log_error "$1 is not installed"
        exit 1
    fi
}

# ─── Pre-flight Checks ─────────────────────────────────────────────
log_step "Pre-flight Checks"

cd "$PROJECT_ROOT"

log_info "Checking required tools..."
check_command go
check_command npm
check_command git
check_command tar
check_command zip

GO_VERSION=$(go version | awk '{print $3}')
NODE_VERSION=$(node --version)
log_success "Go: $GO_VERSION"
log_success "Node: $NODE_VERSION"

# Check for uncommitted changes
if [[ -n $(git status --porcelain) ]]; then
    log_warning "Uncommitted changes detected"
    read -p "Continue anyway? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
DATE=$(date -u '+%Y-%m-%dT%H:%M:%SZ')

log_info "Version: v$VERSION"
log_info "Commit: $COMMIT"
log_info "Date: $DATE"

# ─── Step 1: Run Tests ─────────────────────────────────────────────
log_step "Step 1: Running Tests"

log_info "Running Go tests..."
go test ./... -v -count=1 -timeout 60s
log_success "All Go tests passed"

log_info "Running TypeScript type check..."
cd "$FRONTEND_DIR"
npx tsc --noEmit
log_success "TypeScript check passed"
cd "$PROJECT_ROOT"

# ─── Step 2: Build Frontend ────────────────────────────────────────
log_step "Step 2: Building Frontend"

cd "$FRONTEND_DIR"
log_info "Installing dependencies..."
npm install --prefer-offline --no-audit

log_info "Building React app..."
npm run build
log_success "Frontend built: $FRONTEND_DIR/dist"

# Copy to embed directory
log_info "Copying to embed directory..."
rm -rf "$DIST_DIR"
mkdir -p "$DIST_DIR"
cp -r "$FRONTEND_DIR/dist/"* "$DIST_DIR/"
log_success "Frontend copied to $DIST_DIR"

cd "$PROJECT_ROOT"

# ─── Step 3: Cross-Compile ─────────────────────────────────────────
log_step "Step 3: Cross-Compiling Binaries"

rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"

LDFLAGS="-s -w -X main.version=$VERSION -X main.buildCommit=$COMMIT -X main.buildDate=$DATE"

# Linux amd64
log_info "Building for Linux amd64..."
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "$LDFLAGS" -o "$BUILD_DIR/$BINARY_NAME-linux-amd64" ./cmd/sdwan-triage
log_success "$BINARY_NAME-linux-amd64"

# macOS amd64
log_info "Building for macOS amd64..."
CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -ldflags "$LDFLAGS" -o "$BUILD_DIR/$BINARY_NAME-darwin-amd64" ./cmd/sdwan-triage
if command -v codesign &> /dev/null; then
    codesign -s - --force "$BUILD_DIR/$BINARY_NAME-darwin-amd64" 2>/dev/null || true
fi
log_success "$BINARY_NAME-darwin-amd64"

# macOS arm64 (Apple Silicon)
log_info "Building for macOS arm64..."
CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -ldflags "$LDFLAGS" -o "$BUILD_DIR/$BINARY_NAME-darwin-arm64" ./cmd/sdwan-triage
if command -v codesign &> /dev/null; then
    codesign -s - --force "$BUILD_DIR/$BINARY_NAME-darwin-arm64" 2>/dev/null || true
fi
log_success "$BINARY_NAME-darwin-arm64"

# Windows amd64
log_info "Building for Windows amd64..."
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags "$LDFLAGS" -o "$BUILD_DIR/$BINARY_NAME-windows-amd64.exe" ./cmd/sdwan-triage
log_success "$BINARY_NAME-windows-amd64.exe"

# ─── Step 4: Create Archives ───────────────────────────────────────
log_step "Step 4: Creating Release Archives"

cd "$BUILD_DIR"

log_info "Creating tar.gz archives..."
tar -czf "$BINARY_NAME-v$VERSION-linux-amd64.tar.gz" "$BINARY_NAME-linux-amd64"
tar -czf "$BINARY_NAME-v$VERSION-darwin-amd64.tar.gz" "$BINARY_NAME-darwin-amd64"
tar -czf "$BINARY_NAME-v$VERSION-darwin-arm64.tar.gz" "$BINARY_NAME-darwin-arm64"

log_info "Creating zip archive for Windows..."
zip -j "$BINARY_NAME-v$VERSION-windows-amd64.zip" "$BINARY_NAME-windows-amd64.exe"

log_info "Generating checksums..."
shasum -a 256 *.tar.gz *.zip > "checksums-v$VERSION.txt"

cd "$PROJECT_ROOT"

log_success "Archives created:"
ls -lh "$BUILD_DIR"/*.tar.gz "$BUILD_DIR"/*.zip "$BUILD_DIR"/checksums-*.txt

# ─── Step 5: Create Release Notes ──────────────────────────────────
log_step "Step 5: Generating Release Notes"

RELEASE_NOTES="$PROJECT_ROOT/RELEASE_NOTES.md"
cat > "$RELEASE_NOTES" << EOF
# SD-WAN Triage Tool v$VERSION — Forensic Gold Standard

## 🎯 Highlights

- **Learning Platform**: Sample PCAP library with 5 training scenarios
- **Interactive Glossary**: 25+ network forensics terms with hover tooltips
- **Challenge Mode**: Quiz-style analysis with hidden answers
- **Protocol Hierarchy**: Collapsible tree view of protocol breakdown
- **I/O Graphs**: Time-series throughput visualization with filtering
- **Advanced Filtering**: Wireshark-style autocomplete filter input
- **Packet Colorization**: Heuristic coloring for RST/FIN/retransmissions
- **Keyboard Navigation**: j/k arrows, Enter, Esc, / shortcuts

## 📦 Downloads

| Platform | Architecture | File |
|----------|--------------|------|
| Linux | x86_64 | \`$BINARY_NAME-v$VERSION-linux-amd64.tar.gz\` |
| macOS | Intel | \`$BINARY_NAME-v$VERSION-darwin-amd64.tar.gz\` |
| macOS | Apple Silicon | \`$BINARY_NAME-v$VERSION-darwin-arm64.tar.gz\` |
| Windows | x86_64 | \`$BINARY_NAME-v$VERSION-windows-amd64.zip\` |

## 🔐 Checksums

\`\`\`
$(cat "$BUILD_DIR/checksums-v$VERSION.txt")
\`\`\`

## 🚀 Quick Start

\`\`\`bash
# Extract
tar -xzf $BINARY_NAME-v$VERSION-darwin-arm64.tar.gz

# Run web UI
./$BINARY_NAME-darwin-arm64 -web

# Open browser to http://localhost:8080
\`\`\`

## 📝 Full Changelog

See [CHANGELOG.md](CHANGELOG.md) for complete details.

---
Built with commit \`$COMMIT\` on $DATE
EOF

log_success "Release notes generated: $RELEASE_NOTES"

# ─── Step 6: GitHub Release (Optional) ─────────────────────────────
log_step "Step 6: GitHub Release"

if command -v gh &> /dev/null; then
    if gh auth status &> /dev/null 2>&1; then
        log_info "GitHub CLI authenticated"
        read -p "Create GitHub release? (y/N) " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            log_info "Creating GitHub release v$VERSION..."
            gh release create "v$VERSION" \
                "$BUILD_DIR/$BINARY_NAME-v$VERSION-linux-amd64.tar.gz" \
                "$BUILD_DIR/$BINARY_NAME-v$VERSION-darwin-amd64.tar.gz" \
                "$BUILD_DIR/$BINARY_NAME-v$VERSION-darwin-arm64.tar.gz" \
                "$BUILD_DIR/$BINARY_NAME-v$VERSION-windows-amd64.zip" \
                "$BUILD_DIR/checksums-v$VERSION.txt" \
                --title "v$VERSION - Forensic Gold Standard" \
                --notes-file "$RELEASE_NOTES" \
                --draft
            log_success "GitHub release v$VERSION created (draft)"
            log_info "Review and publish at: https://github.com/gocisse/sdwan-triage/releases"
        else
            log_info "Skipping GitHub release"
        fi
    else
        log_warning "GitHub CLI not authenticated. Run: gh auth login"
    fi
else
    log_warning "GitHub CLI (gh) not installed. Run: brew install gh"
fi

# ─── Summary ───────────────────────────────────────────────────────
log_step "Release Complete!"

echo ""
echo "  Version:   v$VERSION"
echo "  Commit:    $COMMIT"
echo "  Date:      $DATE"
echo ""
echo "  Artifacts:"
ls -1 "$BUILD_DIR"/*.tar.gz "$BUILD_DIR"/*.zip 2>/dev/null | while read f; do
    SIZE=$(ls -lh "$f" | awk '{print $5}')
    echo "    $(basename "$f") ($SIZE)"
done
echo ""
echo "  Checksums: $BUILD_DIR/checksums-v$VERSION.txt"
echo "  Notes:     $RELEASE_NOTES"
echo ""

log_success "Done! 🎉"
