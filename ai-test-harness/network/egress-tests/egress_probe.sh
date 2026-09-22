#!/bin/bash
# Egress probe — run from inside a test container to validate SC-7 boundary controls.
# Logs results as structured output for evidence capture.
set -euo pipefail

OUTPUT_FILE="${1:-/tmp/egress_probe_$(date -u +%Y%m%dT%H%M%SZ).json}"

echo "=== Egress Probe — $(date -u) ==="
echo "Output: $OUTPUT_FILE"
echo ""

results=()

probe() {
    local name="$1"
    local cmd="$2"
    local result
    result=$(eval "$cmd" 2>&1) && status="OPEN" || status="BLOCKED"
    echo "  $name: $status"
    results+=("{\"test\": \"$name\", \"status\": \"$status\", \"detail\": \"$(echo "$result" | head -1 | tr '"' "'")\"}")
}

echo "--- DNS Resolution ---"
probe "dns_resolution" "nslookup example.com"

echo "--- HTTP Egress ---"
probe "http_egress" "curl -s -o /dev/null -w '%{http_code}' --connect-timeout 5 http://example.com"

echo "--- HTTPS Egress ---"
probe "https_egress" "curl -s -o /dev/null -w '%{http_code}' --connect-timeout 5 https://example.com"

echo "--- IMDS v1 ---"
probe "imds_v1" "curl -s --connect-timeout 2 http://169.254.169.254/latest/meta-data/"

echo "--- IMDS v2 ---"
probe "imds_v2_token" "curl -s --connect-timeout 2 -X PUT http://169.254.169.254/latest/api/token -H 'X-aws-ec2-metadata-token-ttl-seconds: 60'"

echo "--- Common Ports ---"
for PORT in 53 80 443 8080 8443; do
    probe "port_${PORT}" "timeout 3 bash -c 'echo test > /dev/tcp/example.com/$PORT' 2>&1"
done

# Write JSON output
echo "[" > "$OUTPUT_FILE"
for i in "${!results[@]}"; do
    if [ $i -gt 0 ]; then
        echo "," >> "$OUTPUT_FILE"
    fi
    echo "  ${results[$i]}" >> "$OUTPUT_FILE"
done
echo "]" >> "$OUTPUT_FILE"

echo ""
echo "Results saved: $OUTPUT_FILE"
