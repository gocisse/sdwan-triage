# SD-WAN Triage Tool - Makefile
# Unified build pipeline: React frontend → embedded Go binary

# ─── VARIABLES ──────────────────────────────────────────────
BINARY_NAME  := sdwan-triage
VERSION      ?= 4.5.2
BUILD_DIR    := build
DIST_DIR     := cmd/sdwan-triage/dist
FRONTEND_DIR := web/frontend
GEOIP_DIR    := data
GEOIP_DB     := $(GEOIP_DIR)/GeoLite2-City.mmdb
GO           := go
COMMIT       := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
DATE         := $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')
LDFLAGS      := -s -w \
                -X main.version=$(VERSION) \
                -X main.buildCommit=$(COMMIT) \
                -X main.buildDate=$(DATE)
GOFLAGS      := -ldflags '$(LDFLAGS)'

.PHONY: all build build-frontend copy-dist build-backend build-all \
        build-linux build-darwin build-windows release \
        clean clean-all test test-coverage test-race \
        lint fmt vet run run-web help \
        setup-geoip check-geoip frontend-dev install

# ─── DEFAULT ────────────────────────────────────────────────
all: build

# ─── FRONTEND ───────────────────────────────────────────────
build-frontend:
	@echo "📦 Building React frontend..."
	cd $(FRONTEND_DIR) && npm install --prefer-offline --no-audit && npm run build
	@echo "✓ Frontend built: $(FRONTEND_DIR)/dist"

copy-dist: build-frontend
	@echo "📋 Copying frontend dist into embed directory..."
	@rm -rf $(DIST_DIR)
	@mkdir -p $(DIST_DIR)
	cp -r $(FRONTEND_DIR)/dist/* $(DIST_DIR)/
	@echo "✓ Frontend copied to $(DIST_DIR)"

# ─── BACKEND ───────────────────────────────────────────────
build-backend:
	@echo "🔨 Building $(BINARY_NAME) v$(VERSION) ($(COMMIT))..."
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 $(GO) build $(GOFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/sdwan-triage
	@echo "✓ Built: $(BUILD_DIR)/$(BINARY_NAME)"

# ─── UNIFIED BUILD (frontend + backend) ────────────────────
build: copy-dist build-backend
	@echo ""
	@echo "══════════════════════════════════════════════════"
	@echo "  ✓ $(BINARY_NAME) v$(VERSION) ready"
	@echo "    Binary: $(BUILD_DIR)/$(BINARY_NAME)"
	@echo "    Commit: $(COMMIT)"
	@echo "    Date:   $(DATE)"
	@echo "══════════════════════════════════════════════════"

# ─── CROSS-COMPILATION ─────────────────────────────────────
build-linux: copy-dist
	@echo "🐧 Building for Linux..."
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build $(GOFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 ./cmd/sdwan-triage
	@echo "✓ $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64"

build-darwin: copy-dist
	@echo "🍎 Building for macOS..."
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 $(GO) build $(GOFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 ./cmd/sdwan-triage
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 $(GO) build $(GOFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 ./cmd/sdwan-triage
	@echo "🔏 Ad-hoc codesigning macOS binaries..."
	codesign -s - --force $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64
	codesign -s - --force $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64
	@echo "✓ $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64"
	@echo "✓ $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64"

build-windows: copy-dist
	@echo "🪟 Building for Windows..."
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 $(GO) build $(GOFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe ./cmd/sdwan-triage
	@echo "✓ $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe"

build-all: build-linux build-darwin build-windows

# ─── RELEASE ────────────────────────────────────────────────
# Builds all platforms, creates checksums, and packages archives
release: clean copy-dist
	@echo "🚀 Building release v$(VERSION)..."
	@mkdir -p $(BUILD_DIR)
	@# Linux amd64
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build $(GOFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 ./cmd/sdwan-triage
	tar -czf $(BUILD_DIR)/$(BINARY_NAME)-v$(VERSION)-linux-amd64.tar.gz -C $(BUILD_DIR) $(BINARY_NAME)-linux-amd64
	@# macOS amd64
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 $(GO) build $(GOFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 ./cmd/sdwan-triage
	codesign -s - --force $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64
	tar -czf $(BUILD_DIR)/$(BINARY_NAME)-v$(VERSION)-darwin-amd64.tar.gz -C $(BUILD_DIR) $(BINARY_NAME)-darwin-amd64
	@# macOS arm64 (Apple Silicon)
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 $(GO) build $(GOFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 ./cmd/sdwan-triage
	codesign -s - --force $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64
	tar -czf $(BUILD_DIR)/$(BINARY_NAME)-v$(VERSION)-darwin-arm64.tar.gz -C $(BUILD_DIR) $(BINARY_NAME)-darwin-arm64
	@# Windows amd64
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 $(GO) build $(GOFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe ./cmd/sdwan-triage
	zip -j $(BUILD_DIR)/$(BINARY_NAME)-v$(VERSION)-windows-amd64.zip $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe
	@# Checksums
	@echo "🔐 Generating checksums..."
	cd $(BUILD_DIR) && shasum -a 256 *.tar.gz *.zip > checksums-v$(VERSION).txt
	@echo ""
	@echo "══════════════════════════════════════════════════"
	@echo "  ✓ Release v$(VERSION) artifacts:"
	@ls -lh $(BUILD_DIR)/*.tar.gz $(BUILD_DIR)/*.zip $(BUILD_DIR)/checksums-*.txt
	@echo "══════════════════════════════════════════════════"

install: copy-dist
	$(GO) install $(GOFLAGS) ./cmd/sdwan-triage

# ─── TEST ───────────────────────────────────────────────────
test:
	@echo "Running tests..."
	$(GO) test ./... -v -count=1 -timeout 60s
	@echo "✓ All tests passed"

test-coverage:
	@echo "Running tests with coverage..."
	$(GO) test ./... -coverprofile=coverage.out -timeout 60s
	$(GO) tool cover -html=coverage.out -o coverage.html
	@echo "✓ Coverage report: coverage.html"

test-race:
	@echo "Running tests with race detector..."
	$(GO) test ./... -race -count=1 -timeout 120s

# ─── CODE QUALITY ───────────────────────────────────────────
fmt:
	$(GO) fmt ./...

vet:
	$(GO) vet ./...

lint: fmt vet
	@echo "✓ Code quality checks passed"

# ─── GEOIP DATABASE ────────────────────────────────────────
setup-geoip:
	@echo "Setting up GeoIP database..."
	@mkdir -p $(GEOIP_DIR)
	@chmod +x scripts/download_geoip.sh
	@scripts/download_geoip.sh $(GEOIP_DIR)
	@echo "✓ GeoIP database ready"

check-geoip:
	@if [ -f "$(GEOIP_DB)" ]; then \
		echo "✓ GeoIP database found: $(GEOIP_DB)"; \
		ls -lh $(GEOIP_DB); \
	else \
		echo "✗ GeoIP database not found. Run: make setup-geoip"; \
	fi

# ─── FRONTEND DEV ──────────────────────────────────────────
frontend-dev:
	cd $(FRONTEND_DIR) && npm run dev

# ─── RUN ────────────────────────────────────────────────────
run:
	$(GO) run $(GOFLAGS) ./cmd/sdwan-triage $(ARGS)

run-web:
	$(GO) run $(GOFLAGS) ./cmd/sdwan-triage -web -port 8080

# ─── CLEAN ──────────────────────────────────────────────────
clean:
	@echo "Cleaning..."
	rm -rf $(BUILD_DIR)
	rm -rf $(DIST_DIR)
	rm -f coverage.out coverage.html
	@echo "✓ Clean"

clean-all: clean
	rm -rf $(GEOIP_DIR)/*.mmdb

# ─── HELP ───────────────────────────────────────────────────
help:
	@echo "SD-WAN Triage Tool v$(VERSION) - Build Targets"
	@echo ""
	@echo "  Build Pipeline:"
	@echo "    make build            Full build: frontend → embed → Go binary"
	@echo "    make build-frontend   Build React frontend only"
	@echo "    make build-backend    Build Go binary only (assumes dist/ exists)"
	@echo "    make build-all        Cross-compile for Linux, macOS, Windows"
	@echo "    make release          Build release archives + checksums for all platforms"
	@echo "    make install          Install to GOPATH/bin"
	@echo ""
	@echo "  Test:"
	@echo "    make test             Run all tests"
	@echo "    make test-coverage    Run tests with coverage report"
	@echo "    make test-race        Run tests with race detector"
	@echo ""
	@echo "  Code Quality:"
	@echo "    make fmt              Format code"
	@echo "    make vet              Run go vet"
	@echo "    make lint             Run all linters"
	@echo ""
	@echo "  GeoIP:"
	@echo "    make setup-geoip      Download GeoIP database"
	@echo "    make check-geoip      Check if GeoIP database exists"
	@echo ""
	@echo "  Run:"
	@echo "    make run ARGS='...'   Run CLI mode with arguments"
	@echo "    make run-web          Run web application mode"
	@echo "    make frontend-dev     Start frontend dev server"
	@echo ""
	@echo "  Clean:"
	@echo "    make clean            Remove build artifacts"
	@echo "    make clean-all        Remove build artifacts and GeoIP data"
	@echo ""
	@echo "  Version: $(VERSION) | Commit: $(COMMIT) | Date: $(DATE)"
