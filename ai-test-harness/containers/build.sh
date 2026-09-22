#!/bin/bash
# Build clean and modified container images with consistent tagging and evidence capture.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
HARNESS_ROOT="$(dirname "$SCRIPT_DIR")"
EVIDENCE_DIR="${HARNESS_ROOT}/evidence/artifacts"
TIMESTAMP=$(date -u +%Y%m%dT%H%M%SZ)

mkdir -p "$EVIDENCE_DIR"

echo "=== Container Build — ${TIMESTAMP} ==="
echo ""

# Build the clean reproduction
if [ -f "${SCRIPT_DIR}/clean/Dockerfile" ]; then
    echo "Building clean image..."
    docker build -t "harness/tei-clean:${TIMESTAMP}" \
        -f "${SCRIPT_DIR}/clean/Dockerfile" "${SCRIPT_DIR}/clean/"
    docker inspect "harness/tei-clean:${TIMESTAMP}" | \
        jq '.[0].Id' > "${EVIDENCE_DIR}/clean_image_id_${TIMESTAMP}.txt"
    echo "  Tagged: harness/tei-clean:${TIMESTAMP}"
else
    echo "  [SKIP] No clean/Dockerfile found"
fi

# Build modified variant(s)
for df in "${SCRIPT_DIR}"/modified/Dockerfile*; do
    if [ -f "$df" ]; then
        variant=$(basename "$df" | sed 's/Dockerfile\.//' | sed 's/Dockerfile/default/')
        echo "Building modified image (${variant})..."
        docker build -t "harness/tei-modified-${variant}:${TIMESTAMP}" \
            -f "$df" "${SCRIPT_DIR}/modified/"
        docker inspect "harness/tei-modified-${variant}:${TIMESTAMP}" | \
            jq '.[0].Id' > "${EVIDENCE_DIR}/modified_${variant}_image_id_${TIMESTAMP}.txt"
        echo "  Tagged: harness/tei-modified-${variant}:${TIMESTAMP}"
    fi
done

# Layer diff (if both exist)
CLEAN_IMG=$(docker images -q "harness/tei-clean:${TIMESTAMP}" 2>/dev/null)
MOD_IMG=$(docker images -q "harness/tei-modified-*:${TIMESTAMP}" 2>/dev/null | head -1)

if [ -n "$CLEAN_IMG" ] && [ -n "$MOD_IMG" ]; then
    echo ""
    echo "=== Layer Diff ==="
    diff <(docker inspect "$CLEAN_IMG" | jq '.[0].RootFS.Layers') \
         <(docker inspect "$MOD_IMG" | jq '.[0].RootFS.Layers') \
         | tee "${EVIDENCE_DIR}/layer_diff_${TIMESTAMP}.txt" || true
fi

echo ""
echo "Build complete at ${TIMESTAMP}"
echo "Evidence: ${EVIDENCE_DIR}"
