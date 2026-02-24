#!/usr/bin/env bash
# download_geoip.sh — Download GeoIP database for SD-WAN Triage Tool
#
# Usage:
#   ./scripts/download_geoip.sh [output_dir]
#
# Environment Variables:
#   MAXMIND_LICENSE_KEY  — MaxMind license key (for GeoLite2)
#                          Get one free at: https://www.maxmind.com/en/geolite2/signup
#
# If no license key is set, falls back to the free DB-IP Lite database.

set -euo pipefail

OUTPUT_DIR="${1:-data}"
mkdir -p "$OUTPUT_DIR"

FINAL_DB="$OUTPUT_DIR/GeoLite2-City.mmdb"

# ─── Option 1: MaxMind GeoLite2 (preferred, requires free license key) ──────
download_maxmind() {
    local key="$MAXMIND_LICENSE_KEY"
    local url="https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=${key}&suffix=tar.gz"
    local tmp_archive
    tmp_archive=$(mktemp /tmp/geolite2-XXXXXX.tar.gz)

    echo "→ Downloading MaxMind GeoLite2-City database..."
    if curl -fsSL -o "$tmp_archive" "$url"; then
        echo "→ Extracting..."
        tar -xzf "$tmp_archive" -C /tmp
        local mmdb
        mmdb=$(find /tmp/GeoLite2-City_* -name '*.mmdb' -print -quit 2>/dev/null || true)
        if [ -n "$mmdb" ]; then
            mv "$mmdb" "$FINAL_DB"
            rm -rf /tmp/GeoLite2-City_* "$tmp_archive"
            echo "✓ GeoLite2-City.mmdb installed to $FINAL_DB"
            return 0
        fi
    fi

    rm -f "$tmp_archive"
    echo "✗ MaxMind download failed"
    return 1
}

# ─── Option 2: DB-IP Lite (free, no key required) ───────────────────────────
download_dbip() {
    local month
    month=$(date +%Y-%m)
    local url="https://download.db-ip.com/free/dbip-city-lite-${month}.mmdb.gz"
    local tmp_gz
    tmp_gz=$(mktemp /tmp/dbip-XXXXXX.mmdb.gz)

    echo "→ Downloading DB-IP Lite City database (${month})..."
    if curl -fsSL -o "$tmp_gz" "$url"; then
        echo "→ Extracting..."
        gunzip -c "$tmp_gz" > "$FINAL_DB"
        rm -f "$tmp_gz"
        echo "✓ DB-IP Lite database installed to $FINAL_DB"
        echo "  (Compatible with MaxMind MMDB reader)"
        return 0
    fi

    rm -f "$tmp_gz"
    echo "✗ DB-IP download failed"
    return 1
}

# ─── Main ────────────────────────────────────────────────────────────────────

# Check if database already exists
if [ -f "$FINAL_DB" ]; then
    size=$(wc -c < "$FINAL_DB" | tr -d ' ')
    if [ "$size" -gt 1000000 ]; then
        echo "✓ GeoIP database already exists: $FINAL_DB ($(du -h "$FINAL_DB" | cut -f1))"
        echo "  Delete it and re-run to update."
        exit 0
    else
        echo "⚠ Existing database looks corrupt (${size} bytes), re-downloading..."
        rm -f "$FINAL_DB"
    fi
fi

# Try MaxMind first if license key is available
if [ -n "${MAXMIND_LICENSE_KEY:-}" ]; then
    echo "MaxMind license key detected."
    if download_maxmind; then
        exit 0
    fi
    echo "Falling back to DB-IP Lite..."
fi

# Fall back to DB-IP Lite (free, no key required)
if download_dbip; then
    exit 0
fi

# Manual fallback instructions
echo ""
echo "━━━ MANUAL SETUP ━━━"
echo ""
echo "Automatic download failed. To set up GeoIP manually:"
echo ""
echo "Option A — MaxMind GeoLite2 (recommended):"
echo "  1. Sign up at https://www.maxmind.com/en/geolite2/signup"
echo "  2. Generate a license key in your account"
echo "  3. Run: MAXMIND_LICENSE_KEY=your_key make setup-geoip"
echo ""
echo "Option B — DB-IP Lite:"
echo "  1. Download from https://db-ip.com/db/download/ip-to-city-lite"
echo "  2. Extract the .mmdb file to: $FINAL_DB"
echo ""
echo "Option C — Continue without GeoIP:"
echo "  The tool works without a GeoIP database using built-in IP range heuristics."
echo "  GeoIP just provides more accurate country/city-level resolution."
echo ""
exit 1
