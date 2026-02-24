#!/bin/bash

# SD-WAN Triage Web Application Build Script
# This script builds the frontend and embeds it into a single Go executable

set -e

VERSION="v4.3.0"
BUILD_DIR="$(cd "$(dirname "$0")" && pwd)"
FRONTEND_DIR="${BUILD_DIR}/frontend"
BACKEND_DIR="${BUILD_DIR}/backend"
RELEASE_DIR="${BUILD_DIR}/releases/${VERSION}"

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║       SD-WAN Triage Web Application Build Script             ║"
echo "║                     Version ${VERSION}                           ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# Create release directory
mkdir -p "${RELEASE_DIR}"

# Step 1: Build Frontend
echo "📦 Step 1: Building React frontend..."
cd "${FRONTEND_DIR}"

# Install dependencies if needed
if [ ! -d "node_modules" ]; then
    echo "   Installing npm dependencies..."
    npm install
fi

# Build frontend
echo "   Building production bundle..."
npm run build

# Copy built files to backend static directory
echo "   Copying build to backend/static..."
rm -rf "${BACKEND_DIR}/static"
mkdir -p "${BACKEND_DIR}/static"
cp -r dist/* "${BACKEND_DIR}/static/"

echo "   ✅ Frontend build complete"
echo ""

# Step 2: Build Backend for multiple platforms
echo "📦 Step 2: Building Go backend..."
cd "${BACKEND_DIR}"

# Download dependencies
echo "   Downloading Go dependencies..."
go mod tidy

# Build for macOS (Intel)
echo "   Building for macOS (amd64)..."
GOOS=darwin GOARCH=amd64 go build -ldflags="-s -w" -o "${RELEASE_DIR}/sdwan-triage-web-darwin-amd64" .

# Build for macOS (Apple Silicon)
echo "   Building for macOS (arm64)..."
GOOS=darwin GOARCH=arm64 go build -ldflags="-s -w" -o "${RELEASE_DIR}/sdwan-triage-web-darwin-arm64" .

# Build for Linux (amd64)
echo "   Building for Linux (amd64)..."
GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o "${RELEASE_DIR}/sdwan-triage-web-linux-amd64" .

# Build for Linux (arm64)
echo "   Building for Linux (arm64)..."
GOOS=linux GOARCH=arm64 go build -ldflags="-s -w" -o "${RELEASE_DIR}/sdwan-triage-web-linux-arm64" .

# Build for Windows
echo "   Building for Windows (amd64)..."
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o "${RELEASE_DIR}/sdwan-triage-web-windows-amd64.exe" .

echo "   ✅ Backend build complete"
echo ""

# Step 3: Create ZIP archives
echo "📦 Step 3: Creating release archives..."
cd "${RELEASE_DIR}"

for binary in sdwan-triage-web-*; do
    if [[ ! "$binary" == *.zip ]]; then
        echo "   Compressing ${binary}..."
        zip -q "${binary}.zip" "${binary}"
    fi
done

# Generate checksums
echo "   Generating checksums..."
shasum -a 256 *.zip > checksums.txt

echo "   ✅ Archives created"
echo ""

# Step 4: Summary
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                    Build Complete!                           ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "Release files are in: ${RELEASE_DIR}"
echo ""
ls -lh "${RELEASE_DIR}"
echo ""
echo "To run the application:"
echo "  macOS (Intel):  ./sdwan-triage-web-darwin-amd64"
echo "  macOS (M1/M2):  ./sdwan-triage-web-darwin-arm64"
echo "  Linux:          ./sdwan-triage-web-linux-amd64"
echo "  Windows:        sdwan-triage-web-windows-amd64.exe"
echo ""
echo "The application will automatically open your browser to:"
echo "  http://127.0.0.1:8080"
