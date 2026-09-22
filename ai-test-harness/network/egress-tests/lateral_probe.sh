#!/bin/bash
# Lateral movement probe — run from inside the test container or EC2 host.
# Discovers adjacent hosts and probes service ports.
set -euo pipefail

OUTPUT_FILE="${1:-/tmp/lateral_probe_$(date -u +%Y%m%dT%H%M%SZ).txt}"

echo "=== Lateral Movement Probe — $(date -u) ===" | tee "$OUTPUT_FILE"

# Detect the local subnet
SUBNET=$(ip route 2>/dev/null | grep -v default | head -1 | awk '{print $1}')
if [ -z "$SUBNET" ]; then
    echo "Could not determine local subnet." | tee -a "$OUTPUT_FILE"
    exit 1
fi

echo "Scanning subnet: $SUBNET" | tee -a "$OUTPUT_FILE"
echo "" | tee -a "$OUTPUT_FILE"

# Host discovery
echo "--- Host Discovery ---" | tee -a "$OUTPUT_FILE"
if command -v nmap &>/dev/null; then
    nmap -sn "$SUBNET" 2>/dev/null | grep "Nmap scan report" | tee -a "$OUTPUT_FILE"
else
    echo "nmap not available — falling back to ping sweep" | tee -a "$OUTPUT_FILE"
    BASE=$(echo "$SUBNET" | cut -d'/' -f1 | rev | cut -d'.' -f2- | rev)
    for i in $(seq 1 254); do
        ping -c 1 -W 1 "${BASE}.${i}" &>/dev/null && echo "  LIVE: ${BASE}.${i}" | tee -a "$OUTPUT_FILE" &
    done
    wait
fi

echo "" | tee -a "$OUTPUT_FILE"

# Port scanning discovered hosts
PROBE_PORTS="22,80,443,5432,3306,6379,8080,8443,9200"

echo "--- Service Probes (ports: $PROBE_PORTS) ---" | tee -a "$OUTPUT_FILE"
if command -v nmap &>/dev/null; then
    for HOST in $(nmap -sn "$SUBNET" 2>/dev/null | grep "report for" | awk '{print $NF}' | tr -d '()'); do
        echo "Host: $HOST" | tee -a "$OUTPUT_FILE"
        nmap -Pn -p "$PROBE_PORTS" --open "$HOST" 2>/dev/null | grep "open" | tee -a "$OUTPUT_FILE"
        echo "" | tee -a "$OUTPUT_FILE"
    done
else
    echo "nmap not available for port scanning" | tee -a "$OUTPUT_FILE"
fi

echo "Results saved: $OUTPUT_FILE"
