#!/bin/bash
# ClamAV Active Response Trigger Script
# This script sends an active response message to trigger ClamAV scans on Windows agents

AGENT_ID="$1"
SCAN_TYPE="${2:-quickscan}"

if [ -z "$AGENT_ID" ]; then
    echo "Usage: $0 <agent_id> [scan_type]"
    echo ""
    echo "Arguments:"
    echo "  agent_id   - The Wazuh agent ID (e.g., 001, 002, 003)"
    echo "  scan_type  - Type of scan: quickscan, fullscan, or customscan (default: quickscan)"
    echo ""
    echo "Examples:"
    echo "  $0 003                    # Quick scan on agent 003"
    echo "  $0 003 fullscan           # Full scan on agent 003"
    echo "  $0 003 customscan         # Custom scan on agent 003"
    exit 1
fi

# Wazuh directories
WAZUH_DIR="/var/ossec"
AR_SOCKET="${WAZUH_DIR}/queue/alerts/ar"
EXECD_SOCKET="${WAZUH_DIR}/queue/alerts/execq"

# Check if running as root or wazuh user
if [ "$EUID" -ne 0 ] && [ "$(whoami)" != "wazuh" ]; then
    echo "Error: This script must be run as root or wazuh user"
    exit 1
fi

# Validate agent exists and is active
AGENT_STATUS=$(${WAZUH_DIR}/bin/agent_control -i ${AGENT_ID} 2>/dev/null | grep -i "status" | awk '{print $NF}')

if [ -z "$AGENT_STATUS" ]; then
    echo "Error: Agent ${AGENT_ID} not found"
    exit 1
fi

if [ "$AGENT_STATUS" != "Active" ]; then
    echo "Warning: Agent ${AGENT_ID} is not active (Status: ${AGENT_STATUS})"
    echo "The active response may not execute."
fi

# Build active response JSON message
AR_MESSAGE=$(cat <<EOF
{
  "version": 1,
  "origin": {
    "name": "manual-trigger",
    "module": "active-response"
  },
  "command": "add",
  "parameters": {
    "extra_args": ["${SCAN_TYPE}"],
    "alert": {
      "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%S.000+0000)",
      "rule": {
        "level": 5,
        "description": "Manual ClamAV scan trigger",
        "id": "100000"
      },
      "agent": {
        "id": "${AGENT_ID}"
      }
    },
    "program": "clamav-scan"
  }
}
EOF
)

echo "Triggering ${SCAN_TYPE} on agent ${AGENT_ID}..."

# Send to active response socket
if [ -S "$EXECD_SOCKET" ]; then
    echo "$AR_MESSAGE" > "$EXECD_SOCKET"
    echo "✓ Active response message sent successfully"
    echo ""
    echo "Monitor the following logs for execution:"
    echo "  Manager: ${WAZUH_DIR}/logs/active-responses.log"
    echo "  Agent:   C:\\Program Files\\monitoring-agent\\active-response\\active-responses.log"
    echo "  Scan:    C:\\Program Files\\monitoring-agent\\clamav\\logs\\clamscan.log"
else
    echo "Error: Active response socket not found at ${EXECD_SOCKET}"
    echo "Is wazuh-execd running?"
    exit 1
fi
