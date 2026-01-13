#!/bin/bash
#
# SD-WAN Triage - Legacy Code Cleanup Script
# 
# This script removes the legacy monolithic main.go file (5678 lines)
# that has been replaced by the modular cmd/sdwan-triage/main.go (410 lines)
#
# Date: January 13, 2026
# Status: Refactoring complete, cleanup pending
#

set -e  # Exit on error

echo "=========================================="
echo "SD-WAN Triage - Legacy Code Cleanup"
echo "=========================================="
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check if we're in the right directory
if [ ! -f "go.mod" ] || [ ! -d "cmd/sdwan-triage" ]; then
    echo -e "${RED}Error: This script must be run from the project root directory${NC}"
    exit 1
fi

echo -e "${BLUE}Current directory:${NC} $(pwd)"
echo ""

# Verify the active main.go exists
if [ ! -f "cmd/sdwan-triage/main.go" ]; then
    echo -e "${RED}Error: Active main.go not found at cmd/sdwan-triage/main.go${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Active main.go found:${NC} cmd/sdwan-triage/main.go"
ACTIVE_LINES=$(wc -l < cmd/sdwan-triage/main.go | tr -d ' ')
echo -e "  Lines: ${ACTIVE_LINES}"
echo ""

# Check for legacy files
LEGACY_FILES=()
if [ -f "main.go" ]; then
    LEGACY_LINES=$(wc -l < main.go | tr -d ' ')
    echo -e "${YELLOW}⚠ Legacy file found:${NC} main.go (${LEGACY_LINES} lines)"
    LEGACY_FILES+=("main.go")
fi

if [ -f "html_integration.go" ]; then
    HTML_LINES=$(wc -l < html_integration.go | tr -d ' ')
    echo -e "${YELLOW}⚠ Legacy file found:${NC} html_integration.go (${HTML_LINES} lines)"
    LEGACY_FILES+=("html_integration.go")
fi

if [ ${#LEGACY_FILES[@]} -eq 0 ]; then
    echo -e "${GREEN}✓ No legacy files found - cleanup already complete!${NC}"
    exit 0
fi

echo ""
echo "=========================================="
echo "Cleanup Plan"
echo "=========================================="
echo ""
echo "The following legacy files will be archived and removed:"
for file in "${LEGACY_FILES[@]}"; do
    echo "  - $file"
done
echo ""

# Ask for confirmation
read -p "Do you want to proceed with cleanup? (yes/no): " -r
echo ""
if [[ ! $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then
    echo -e "${YELLOW}Cleanup cancelled by user${NC}"
    exit 0
fi

# Create archive directory
ARCHIVE_DIR="archive/legacy_$(date +%Y%m%d_%H%M%S)"
echo -e "${BLUE}Creating archive directory:${NC} ${ARCHIVE_DIR}"
mkdir -p "${ARCHIVE_DIR}"
echo ""

# Archive and remove legacy files
for file in "${LEGACY_FILES[@]}"; do
    echo -e "${BLUE}Archiving:${NC} ${file}"
    cp "${file}" "${ARCHIVE_DIR}/${file}.bak"
    echo -e "${GREEN}✓ Backed up to:${NC} ${ARCHIVE_DIR}/${file}.bak"
    
    echo -e "${BLUE}Removing:${NC} ${file}"
    rm "${file}"
    echo -e "${GREEN}✓ Removed${NC}"
    echo ""
done

# Verify build still works
echo "=========================================="
echo "Verification"
echo "=========================================="
echo ""
echo -e "${BLUE}Building project to verify...${NC}"
if go build -o sdwan-triage ./cmd/sdwan-triage; then
    echo -e "${GREEN}✓ Build successful!${NC}"
    rm -f sdwan-triage  # Clean up test binary
else
    echo -e "${RED}✗ Build failed!${NC}"
    echo ""
    echo -e "${YELLOW}Restoring legacy files...${NC}"
    for file in "${LEGACY_FILES[@]}"; do
        cp "${ARCHIVE_DIR}/${file}.bak" "${file}"
        echo -e "${GREEN}✓ Restored:${NC} ${file}"
    done
    echo ""
    echo -e "${RED}Cleanup aborted - legacy files restored${NC}"
    exit 1
fi

echo ""
echo "=========================================="
echo "Cleanup Complete!"
echo "=========================================="
echo ""
echo -e "${GREEN}✓ Legacy files archived to:${NC} ${ARCHIVE_DIR}"
echo -e "${GREEN}✓ Build verification passed${NC}"
echo -e "${GREEN}✓ Project is now clean and modular${NC}"
echo ""
echo "Summary:"
echo "  - Active main.go: cmd/sdwan-triage/main.go (${ACTIVE_LINES} lines)"
echo "  - Legacy files removed: ${#LEGACY_FILES[@]}"
echo "  - Archive location: ${ARCHIVE_DIR}"
echo ""
echo -e "${BLUE}Next steps:${NC}"
echo "  1. Test the tool: ./sdwan-triage --help"
echo "  2. Run with test PCAP: ./sdwan-triage -html report.html TestFile.pcap"
echo "  3. Commit changes: git add -A && git commit -m 'Remove legacy monolithic main.go'"
echo "  4. Push to remote: git push origin main"
echo ""
echo -e "${GREEN}Refactoring complete! 🎉${NC}"
