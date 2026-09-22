#!/bin/bash
# Timestamp and hash evidence files (screenshots, captures, etc.)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
HARNESS_ROOT="$(dirname "$SCRIPT_DIR")"
EVIDENCE_DIR="${HARNESS_ROOT}/evidence"
TIMESTAMP=$(date -u +%Y%m%dT%H%M%SZ)

if [ $# -lt 2 ]; then
    echo "Usage: timestamp.sh <category> <description> [file_to_copy]"
    echo ""
    echo "  category:    e.g. model-lab, api-testing, network, supply-chain"
    echo "  description: brief description of what was captured"
    echo "  file:        (optional) file to copy into evidence with timestamp"
    echo ""
    echo "If no file is given and a screenshot tool is available, takes a screenshot."
    exit 1
fi

CATEGORY="$1"
DESC="$2"
SOURCE_FILE="${3:-}"

if [ -n "$SOURCE_FILE" ]; then
    EXT="${SOURCE_FILE##*.}"
    DEST="${EVIDENCE_DIR}/artifacts/${CATEGORY}_${TIMESTAMP}.${EXT}"
    cp "$SOURCE_FILE" "$DEST"
    echo "Copied: $SOURCE_FILE -> $DEST"
elif command -v screencapture &>/dev/null; then
    DEST="${EVIDENCE_DIR}/screenshots/${CATEGORY}_${TIMESTAMP}.png"
    screencapture -i "$DEST"
    echo "Screenshot saved: $DEST"
elif command -v scrot &>/dev/null; then
    DEST="${EVIDENCE_DIR}/screenshots/${CATEGORY}_${TIMESTAMP}.png"
    scrot -s "$DEST"
    echo "Screenshot saved: $DEST"
else
    echo "No screenshot tool available and no file provided."
    echo "Save your evidence file manually, then re-run with the file path."
    exit 1
fi

HASH=$(sha256sum "$DEST" | awk '{print $1}')
echo "SHA-256: $HASH"

python3 "${SCRIPT_DIR}/evidence.py" log "$DESC" "$CATEGORY" \
    --artifact "$DEST" 2>/dev/null || true
