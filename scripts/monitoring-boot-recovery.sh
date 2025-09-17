#!/bin/bash
# Monitoring Agent Boot Recovery Script
# Ensures the agent starts properly after system restart
# Copyright (C) 2025, Monitoring Solutions Inc.

set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly AGENT_HOME="$(dirname "$SCRIPT_DIR")"
readonly CONTROL_SCRIPT="${AGENT_HOME}/monitoring-agent-control.sh"
readonly LOG_FILE="${AGENT_HOME}/logs/boot-recovery.log"

# Logging function
log() {
    local level="$1"
    local message="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local log_entry="[$timestamp] [$level] [BOOT-RECOVERY] $message"
    
    echo "$log_entry" | tee -a "$LOG_FILE"
    
    # Log to systemd journal
    case "$level" in
        "ERROR"|"CRITICAL")
            echo "$log_entry" >&2
            ;;
        *)
            echo "$log_entry"
            ;;
    esac
}

# Wait for system to be fully ready
wait_for_system_ready() {
    log "INFO" "Waiting for system to be fully ready..."
    
    # Wait for network
    local network_ready=false
    for i in {1..30}; do
        if ip route | grep -q default; then
            network_ready=true
            break
        fi
        sleep 2
    done
    
    if [ "$network_ready" = false ]; then
        log "WARN" "Network may not be fully ready"
    else
        log "INFO" "Network is ready"
    fi
    
    # Wait for filesystem to be ready
    if [ -d "${AGENT_HOME}" ]; then
        log "INFO" "Agent home directory accessible"
    else
        log "ERROR" "Agent home directory not accessible: ${AGENT_HOME}"
        exit 1
    fi
    
    # Additional delay to ensure system stability
    sleep 5
}

# Fix any permission issues that may have occurred during restart
fix_permissions() {
    log "INFO" "Checking and fixing permissions after boot..."
    
    # Ensure proper ownership and permissions
    chown -R monitoring:monitoring "${AGENT_HOME}" 2>/dev/null || true
    
    # Fix specific file permissions
    chmod 755 "${AGENT_HOME}" 2>/dev/null || true
    chmod 755 "${AGENT_HOME}/bin"/* 2>/dev/null || true
    chmod 755 "${AGENT_HOME}/scripts"/* 2>/dev/null || true
    chmod 644 "${AGENT_HOME}/etc/ossec.conf" 2>/dev/null || true
    chmod 640 "${AGENT_HOME}/etc/client.keys" 2>/dev/null || true
    
    # Ensure directories exist
    mkdir -p "${AGENT_HOME}/var/run" "${AGENT_HOME}/logs" "${AGENT_HOME}/tmp" 2>/dev/null || true
    
    log "INFO" "Permissions fixed"
}

# Check if agent was running before shutdown
check_previous_state() {
    local state_file="${AGENT_HOME}/var/state/was_running"
    
    if [ -f "$state_file" ]; then
        log "INFO" "Agent was running before shutdown - will restart"
        return 0
    else
        log "INFO" "Agent was not running before shutdown - will not auto-start"
        return 1
    fi
}

# Mark agent as running (for future boot checks)
mark_running_state() {
    mkdir -p "${AGENT_HOME}/var/state" 2>/dev/null || true
    touch "${AGENT_HOME}/var/state/was_running"
}

# Mark agent as stopped (for future boot checks)
mark_stopped_state() {
    rm -f "${AGENT_HOME}/var/state/was_running" 2>/dev/null || true
}

# Perform comprehensive recovery
perform_recovery() {
    log "INFO" "Starting boot recovery process..."
    
    wait_for_system_ready
    fix_permissions
    
    # Always try to start the agent on boot if it was previously running
    if check_previous_state || [ "${FORCE_START:-}" = "true" ]; then
        log "INFO" "Starting monitoring agent..."
        
        if "$CONTROL_SCRIPT" start; then
            mark_running_state
            log "INFO" "Boot recovery successful - agent started"
            
            # Run health check after startup
            sleep 10
            if "$CONTROL_SCRIPT" health-check-full; then
                log "INFO" "Health check passed after boot recovery"
            else
                log "WARN" "Health check failed after boot recovery"
            fi
        else
            log "ERROR" "Failed to start agent during boot recovery"
            exit 1
        fi
    else
        log "INFO" "Agent not started - was not running before shutdown"
    fi
}

# Handle script arguments
case "${1:-recovery}" in
    "recovery")
        perform_recovery
        ;;
    "mark-running")
        mark_running_state
        log "INFO" "Marked agent as running"
        ;;
    "mark-stopped")
        mark_stopped_state
        log "INFO" "Marked agent as stopped"
        ;;
    "check-state")
        if check_previous_state; then
            echo "Agent was running before shutdown"
            exit 0
        else
            echo "Agent was not running before shutdown"
            exit 1
        fi
        ;;
    *)
        echo "Usage: $0 {recovery|mark-running|mark-stopped|check-state}"
        exit 1
        ;;
esac
