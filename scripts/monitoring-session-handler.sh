#!/bin/bash
# Monitoring Agent Session Handler
# Handles user session events

set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly AGENT_HOME="$(dirname "$SCRIPT_DIR")"
readonly LOG_FILE="${AGENT_HOME}/logs/monitoring-agent.log"

log() {
    local level="$1"
    local message="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [$level] [SESSION] $message" >> "$LOG_FILE"
}

# Register for session events
log "INFO" "Session handler started for user: $USER"

# Monitor for session events using dbus (if available)
if command -v dbus-monitor >/dev/null 2>&1; then
    dbus-monitor --session "type='signal',interface='org.freedesktop.ScreenSaver'" 2>/dev/null | while read -r line; do
        if echo "$line" | grep -q "boolean true"; then
            log "INFO" "Screen locked - checking agent health"
            "${AGENT_HOME}/monitoring-agent-control.sh" health-check &>/dev/null || log "WARN" "Health check failed after screen lock"
        elif echo "$line" | grep -q "boolean false"; then
            log "INFO" "Screen unlocked - checking agent health"
            "${AGENT_HOME}/monitoring-agent-control.sh" health-check &>/dev/null || log "WARN" "Health check failed after screen unlock"
        fi
    done &
fi

# Keep the script running
while true; do
    sleep 300  # Check every 5 minutes
    if ! pgrep -f "monitoring-agentd" >/dev/null; then
        log "WARN" "Agent not running - user session may need restart"
    fi
done
