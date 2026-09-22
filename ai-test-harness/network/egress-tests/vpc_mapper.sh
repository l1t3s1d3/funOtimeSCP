#!/bin/bash
# VPC network mapping — queries AWS for security groups, NACLs, and flow logs.
# Requires AWS CLI configured with the test profile.
set -euo pipefail

PROFILE="${AWS_PROFILE:-test-profile}"
OUTPUT_DIR="${1:-/tmp/vpc_map_$(date -u +%Y%m%dT%H%M%SZ)}"

mkdir -p "$OUTPUT_DIR"

echo "=== VPC Network Mapping — $(date -u) ==="
echo "Profile: $PROFILE"
echo "Output: $OUTPUT_DIR"
echo ""

# Security groups
echo "--- Security Groups ---"
if [ -n "${SG_IDS:-}" ]; then
    aws ec2 describe-security-groups \
        --filters "Name=group-id,Values=${SG_IDS}" \
        --profile "$PROFILE" \
        --output json > "${OUTPUT_DIR}/security_groups.json"
    jq '.SecurityGroups[].IpPermissions' "${OUTPUT_DIR}/security_groups.json"
else
    echo "Set SG_IDS env var to query specific security groups."
    echo "  export SG_IDS=sg-xxx,sg-yyy"
fi

# NACLs
echo ""
echo "--- NACLs ---"
if [ -n "${SUBNET_ID:-}" ]; then
    aws ec2 describe-network-acls \
        --filters "Name=association.subnet-id,Values=${SUBNET_ID}" \
        --profile "$PROFILE" \
        --output json > "${OUTPUT_DIR}/nacls.json"
    jq '.NetworkAcls[].Entries' "${OUTPUT_DIR}/nacls.json"
else
    echo "Set SUBNET_ID env var to query NACLs."
fi

# VPC Flow Logs
echo ""
echo "--- VPC Flow Logs ---"
if [ -n "${VPC_ID:-}" ]; then
    aws ec2 describe-flow-logs \
        --filter "Name=resource-id,Values=${VPC_ID}" \
        --profile "$PROFILE" \
        --output json > "${OUTPUT_DIR}/flow_logs.json"
    jq '.FlowLogs[] | {FlowLogId, LogDestination, TrafficType}' \
        "${OUTPUT_DIR}/flow_logs.json"
else
    echo "Set VPC_ID env var to query flow logs."
fi

echo ""
echo "Network mapping saved to: $OUTPUT_DIR"
