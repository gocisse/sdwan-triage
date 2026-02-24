#!/bin/bash
set -euo pipefail

# ─── Configuration ────────────────────────────────────────────────────────────
VERSION="v4.3.2"
VERSION_NUM="${VERSION#v}"  # Strip 'v' prefix for ldflags (main.go format strings add 'v')
COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
DATE=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS="-s -w -X main.version=${VERSION_NUM} -X main.buildCommit=${COMMIT} -X main.buildDate=${DATE}"

RELEASE_DIR="releases/${VERSION}"
BUILD_DIR="cmd/sdwan-triage"
FRONTEND_DIR="web/frontend"
EMBED_DIR="${BUILD_DIR}/dist"

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  SD-WAN Triage Release Builder                              ║"
echo "║  Version: ${VERSION}  Commit: ${COMMIT}                     ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# ─── Step 1: Build Frontend ──────────────────────────────────────────────────
echo "▶ [1/4] Building frontend..."
(cd "${FRONTEND_DIR}" && npm ci --silent && npm run build)
rm -rf "${EMBED_DIR}"
cp -r "${FRONTEND_DIR}/dist" "${EMBED_DIR}"
echo "  ✓ Frontend built and copied to ${EMBED_DIR}"

# ─── Step 2: Create release directory ────────────────────────────────────────
echo "▶ [2/4] Preparing release directory..."
rm -rf "${RELEASE_DIR}"
mkdir -p "${RELEASE_DIR}"

# ─── Step 3: Cross-compile ───────────────────────────────────────────────────
echo "▶ [3/4] Cross-compiling binaries..."

# Target matrix: OS ARCH BINARY_SUFFIX ARCHIVE_TYPE
TARGETS=(
  "darwin   amd64  sdwan-triage-darwin-amd64    tar.gz"
  "darwin   arm64  sdwan-triage-darwin-arm64    tar.gz"
  "linux    amd64  sdwan-triage-linux-amd64     tar.gz"
  "linux    arm64  sdwan-triage-linux-arm64     tar.gz"
  "windows  amd64  sdwan-triage-windows-amd64   zip"
)

for target in "${TARGETS[@]}"; do
  read -r OS ARCH BINARY ARCHIVE_TYPE <<< "${target}"

  BINARY_NAME="${BINARY}"
  [[ "${OS}" == "windows" ]] && BINARY_NAME="${BINARY}.exe"

  echo "  Building ${OS}/${ARCH}..."
  CGO_ENABLED=0 GOOS="${OS}" GOARCH="${ARCH}" \
    go build -ldflags "${LDFLAGS}" -trimpath \
    -o "${RELEASE_DIR}/${BINARY_NAME}" "./${BUILD_DIR}"

  # Package
  ARCHIVE_NAME="sdwan-triage-${VERSION}-${OS}-${ARCH}"
  if [[ "${ARCHIVE_TYPE}" == "tar.gz" ]]; then
    tar -czf "${RELEASE_DIR}/${ARCHIVE_NAME}.tar.gz" \
      -C "${RELEASE_DIR}" "${BINARY_NAME}" \
      -C "$(pwd)" README.md LICENSE 2>/dev/null || \
    tar -czf "${RELEASE_DIR}/${ARCHIVE_NAME}.tar.gz" \
      -C "${RELEASE_DIR}" "${BINARY_NAME}"
    echo "    ✓ ${ARCHIVE_NAME}.tar.gz"
  else
    (cd "${RELEASE_DIR}" && zip -q "${ARCHIVE_NAME}.zip" "${BINARY_NAME}")
    echo "    ✓ ${ARCHIVE_NAME}.zip"
  fi

  # Clean up raw binary to save disk space
  rm -f "${RELEASE_DIR}/${BINARY_NAME}"
done

# ─── Step 4: Checksums ──────────────────────────────────────────────────────
echo "▶ [4/4] Generating checksums..."
(cd "${RELEASE_DIR}" && shasum -a 256 *.tar.gz *.zip > "checksums-${VERSION}.txt")
echo "  ✓ checksums-${VERSION}.txt"

# ─── Summary ─────────────────────────────────────────────────────────────────
echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  Release ${VERSION} built successfully!"
echo "═══════════════════════════════════════════════════════════════"
echo ""
echo "Release artifacts:"
ls -lh "${RELEASE_DIR}"
echo ""
echo "Upload these files to GitHub Releases:"
echo "  gh release create ${VERSION} ${RELEASE_DIR}/*.tar.gz ${RELEASE_DIR}/*.zip ${RELEASE_DIR}/checksums-${VERSION}.txt \\"
echo "    --title 'SD-WAN Triage ${VERSION}' \\"
echo "    --notes-file RELEASE_NOTES.md"
