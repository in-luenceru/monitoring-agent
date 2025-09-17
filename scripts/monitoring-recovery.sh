#!/bin/bash
# Monitoring Agent Recovery Service
# Performs periodic health checks and recovery actions
# Copyright (C) 2025, Monitoring Solutions Inc.

set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly AGENT_HOME="$(dirname "$SCRIPT_DIR")"
readonly LOG_FILE="${AGENT_HOME}/logs/monitoring-agent.log"
readonly RECOVERY_LOG="${AGENT_HOME}/logs/monitoring-recovery.log"
readonly CONTROL_SCRIPT="${AGENT_HOME}/monitoring-agent-control.sh"
readonly CONFIG_FILE="${AGENT_HOME}/etc/ossec.conf"
readonly CLIENT_KEYS="${AGENT_HOME}/etc/client.keys"

# Recovery configuration
readonly HEALTH_CHECK_TIMEOUT=60
readonly RECOVERY_ATTEMPTS=3

# Logging function
log() {
    local level="$1"
    local message="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local log_entry="[$timestamp] [$level] [RECOVERY] $message"
    
    echo "$log_entry" | tee -a "$RECOVERY_LOG" >> "$LOG_FILE"
    
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

# Comprehensive health check
perform_health_check() {
    log "INFO" "Performing comprehensive health check"
    
    local errors=0
    local warnings=0
    
    # Check if main service is active
    if ! systemctl is-active --quiet monitoring-agent.service; then
        log "ERROR" "Main monitoring-agent.service is not active"
        errors=$((errors + 1))
    fi
    
    # Check critical files
    local critical_files=("$CONFIG_FILE" "$CLIENT_KEYS")
    for file in "${critical_files[@]}"; do
        if [[ ! -f "$file" ]]; then
            log "ERROR" "Critical file missing: $file"
            errors=$((errors + 1))
        elif [[ ! -r "$file" ]]; then
            log "ERROR" "Critical file not readable: $file"
            errors=$((errors + 1))
        fi
    done
    
    # Check configuration validity
    if [[ -f "$CONFIG_FILE" ]]; then
        if ! "$CONTROL_SCRIPT" test-config &>/dev/null; then
            log "ERROR" "Configuration validation failed"
            errors=$((errors + 1))
        fi
    fi
    
    # Check disk space
    local disk_usage=$(df "${AGENT_HOME}" | awk 'NR==2 {print $5}' | sed 's/%//')
    if [[ $disk_usage -gt 95 ]]; then
        log "ERROR" "Critical disk space: ${disk_usage}% used"
        errors=$((errors + 1))
    elif [[ $disk_usage -gt 85 ]]; then
        log "WARN" "High disk usage: ${disk_usage}% used"
        warnings=$((warnings + 1))
    fi
    
    # Check memory usage
    local mem_available=$(free -m | awk 'NR==2{printf "%.0f", $7/$2*100}')
    if [[ $mem_available -lt 5 ]]; then
        log "ERROR" "Critical memory shortage: ${mem_available}% available"
        errors=$((errors + 1))
    elif [[ $mem_available -lt 15 ]]; then
        log "WARN" "Low memory: ${mem_available}% available"
        warnings=$((warnings + 1))
    fi
    
    # Check log file sizes
    local log_dir="${AGENT_HOME}/logs"
    if [[ -d "$log_dir" ]]; then
        local large_logs=$(find "$log_dir" -name "*.log" -size +100M 2>/dev/null || true)
        if [[ -n "$large_logs" ]]; then
            log "WARN" "Large log files detected: $large_logs"
            warnings=$((warnings + 1))
        fi
    fi
    
    # Check process health via control script
    if ! timeout $HEALTH_CHECK_TIMEOUT "$CONTROL_SCRIPT" health &>/dev/null; then
        log "ERROR" "Agent health check failed"
        errors=$((errors + 1))
    fi
    
    # Check connectivity (if enrolled)
    if [[ -f "$CLIENT_KEYS" ]] && [[ -s "$CLIENT_KEYS" ]]; then
        if ! timeout $HEALTH_CHECK_TIMEOUT "$CONTROL_SCRIPT" test-connection &>/dev/null; then
            log "WARN" "Connectivity check failed - agent may be isolated"
            warnings=$((warnings + 1))
        fi
    fi
    
    log "INFO" "Health check completed: $errors errors, $warnings warnings"
    
    if [[ $errors -gt 0 ]]; then
        return 1  # Health check failed
    elif [[ $warnings -gt 0 ]]; then
        return 2  # Health check passed with warnings
    else
        return 0  # Health check passed
    fi
}

# Attempt to recover the agent
attempt_recovery() {
    local attempt="$1"
    log "INFO" "Recovery attempt $attempt of $RECOVERY_ATTEMPTS"
    
    # Try to restart the main service
    log "INFO" "Restarting monitoring-agent.service"
    if systemctl restart monitoring-agent.service; then
        log "INFO" "Service restart initiated"
        
        # Wait for service to stabilize
        sleep 15
        
        # Check if recovery was successful
        if systemctl is-active --quiet monitoring-agent.service; then
            log "INFO" "Service is now active"
            
            # Additional health check
            if timeout $HEALTH_CHECK_TIMEOUT "$CONTROL_SCRIPT" health &>/dev/null; then
                log "INFO" "Recovery successful - agent is healthy"
                return 0
            else
                log "WARN" "Service is active but health check still fails"
                return 1
            fi
        else
            log "ERROR" "Service failed to become active after restart"
            return 1
        fi
    else
        log "ERROR" "Failed to restart monitoring-agent.service"
        return 1
    fi
}

# Clean up temporary files and logs
cleanup_environment() {
    log "INFO" "Performing environment cleanup"
    
    # Clean temporary files
    local tmp_dir="${AGENT_HOME}/tmp"
    if [[ -d "$tmp_dir" ]]; then
        find "$tmp_dir" -type f -mtime +1 -delete 2>/dev/null || true
        log "DEBUG" "Cleaned temporary files"
    fi
    
    # Rotate large log files
    local log_dir="${AGENT_HOME}/logs"
    if [[ -d "$log_dir" ]]; then
        find "$log_dir" -name "*.log" -size +100M -exec sh -c '
            for file; do
                mv "$file" "${file}.old.$(date +%Y%m%d-%H%M%S)"
                touch "$file"
                echo "Rotated large log file: $file"
            done
        ' sh {} +
    fi
    
    # Clean old health reports
    find "${AGENT_HOME}/logs" -name "health-report-*.log" -mtime +7 -delete 2>/dev/null || true
    
    # Clean old backup files
    local backup_dir="${AGENT_HOME}/backup"
    if [[ -d "$backup_dir" ]]; then
        find "$backup_dir" -type d -mtime +30 -exec rm -rf {} + 2>/dev/null || true
        log "DEBUG" "Cleaned old backup files"
    fi
    
    log "INFO" "Environment cleanup completed"
}

# Send recovery notification
send_notification() {
    local status="$1"
    local message="$2"
    
    # Notify systemd
    if command -v systemd-notify >/dev/null 2>&1; then
        systemd-notify --status="$status: $message"
    fi
    
    # Log to system journal
    logger -t monitoring-agent-recovery "$status: $message"
    
    # Create notification file for external monitoring
    local notification_file="${AGENT_HOME}/var/run/recovery-notification"
    echo "$(date +%s):$status:$message" > "$notification_file"
}

# Main recovery function
main() {
    log "INFO" "Starting monitoring agent recovery process"
    
    # Ensure log directory exists
    mkdir -p "$(dirname "$RECOVERY_LOG")" 2>/dev/null || true
    
    # Perform initial health check
    local health_status
    if perform_health_check; then
        health_status="HEALTHY"
        log "INFO" "Agent is healthy - no recovery needed"
        send_notification "HEALTHY" "Agent health check passed"
        
        # Still perform cleanup
        cleanup_environment
        return 0
    elif [[ $? -eq 2 ]]; then
        health_status="WARNING"
        log "WARN" "Agent has warnings but is functional"
        send_notification "WARNING" "Agent health check passed with warnings"
        
        # Perform cleanup and return success
        cleanup_environment
        return 0
    else
        health_status="UNHEALTHY"
        log "ERROR" "Agent health check failed - attempting recovery"
        send_notification "UNHEALTHY" "Agent health check failed"
    fi
    
    # Attempt recovery
    local recovery_successful=false
    for ((attempt=1; attempt<=RECOVERY_ATTEMPTS; attempt++)); do
        if attempt_recovery "$attempt"; then
            recovery_successful=true
            break
        else
            log "ERROR" "Recovery attempt $attempt failed"
            if [[ $attempt -lt $RECOVERY_ATTEMPTS ]]; then
                log "INFO" "Waiting 30 seconds before next attempt"
                sleep 30
            fi
        fi
    done
    
    # Final status check
    if [[ "$recovery_successful" == "true" ]]; then
        log "INFO" "Recovery completed successfully"
        send_notification "RECOVERED" "Agent recovery completed successfully"
        cleanup_environment
        return 0
    else
        log "CRITICAL" "All recovery attempts failed - manual intervention required"
        send_notification "FAILED" "Agent recovery failed - manual intervention required"
        
        # Create emergency marker file
        touch "${AGENT_HOME}/var/run/recovery-failed"
        
        return 1
    fi
}

# Signal handlers
cleanup() {
    log "INFO" "Recovery process interrupted"
    exit 130
}

trap cleanup TERM INT

# Run main function
main "$@"