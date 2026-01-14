#!/bin/bash

VERSION="v3.1.0"
RELEASE_DIR="releases/${VERSION}"
BUILD_DIR="cmd/sdwan-triage"

echo "Building SD-WAN Triage ${VERSION} for multiple platforms..."

# Create release directory
mkdir -p "${RELEASE_DIR}"

# Build for macOS (Intel)
echo "Building for macOS (amd64)..."
GOOS=darwin GOARCH=amd64 go build -o "${RELEASE_DIR}/sdwan-triage-darwin-amd64" ./${BUILD_DIR}
zip -j "${RELEASE_DIR}/sdwan-triage-darwin-amd64.zip" "${RELEASE_DIR}/sdwan-triage-darwin-amd64"

# Build for macOS (Apple Silicon)
echo "Building for macOS (arm64)..."
GOOS=darwin GOARCH=arm64 go build -o "${RELEASE_DIR}/sdwan-triage-darwin-arm64" ./${BUILD_DIR}
zip -j "${RELEASE_DIR}/sdwan-triage-darwin-arm64.zip" "${RELEASE_DIR}/sdwan-triage-darwin-arm64"

# Build for Linux (amd64)
echo "Building for Linux (amd64)..."
GOOS=linux GOARCH=amd64 go build -o "${RELEASE_DIR}/sdwan-triage-linux-amd64" ./${BUILD_DIR}
zip -j "${RELEASE_DIR}/sdwan-triage-linux-amd64.zip" "${RELEASE_DIR}/sdwan-triage-linux-amd64"

# Build for Linux (arm64)
echo "Building for Linux (arm64)..."
GOOS=linux GOARCH=arm64 go build -o "${RELEASE_DIR}/sdwan-triage-linux-arm64" ./${BUILD_DIR}
zip -j "${RELEASE_DIR}/sdwan-triage-linux-arm64.zip" "${RELEASE_DIR}/sdwan-triage-linux-arm64"

# Build for Windows (amd64)
echo "Building for Windows (amd64)..."
GOOS=windows GOARCH=amd64 go build -o "${RELEASE_DIR}/sdwan-triage-windows-amd64.exe" ./${BUILD_DIR}
zip -j "${RELEASE_DIR}/sdwan-triage-windows-amd64.zip" "${RELEASE_DIR}/sdwan-triage-windows-amd64.exe"

# Generate checksums
echo "Generating checksums..."
cd "${RELEASE_DIR}"
shasum -a 256 sdwan-triage-* > checksums.txt
cd ../..

echo "Build complete! Release files are in ${RELEASE_DIR}"
echo ""
echo "Files created:"
ls -lh "${RELEASE_DIR}"
