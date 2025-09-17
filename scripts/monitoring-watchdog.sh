#!/bin/bash
# Monitoring Agent Process Watchdog
# Continuously monitors critical processes and restarts them if needed
# Copyright (C) 2025, Monitoring Solutions Inc.

set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly AGENT_HOME="$(dirname "$SCRIPT_DIR")"
readonly LOG_FILE="${AGENT_HOME}/logs/monitoring-agent.log"
readonly WATCHDOG_LOG="${AGENT_HOME}/logs/monitoring-watchdog.log"
readonly CONTROL_SCRIPT="${AGENT_HOME}/monitoring-agent-control.sh"
readonly PID_DIR="${AGENT_HOME}/var/run"
readonly CONFIG_FILE="${AGENT_HOME}/etc/ossec.conf"

# Watchdog configuration
readonly CHECK_INTERVAL=30  # seconds
readonly MAX_RESTART_ATTEMPTS=3
readonly RESTART_COOLDOWN=300  # 5 minutes
readonly CRITICAL_PROCESSES="monitoring-agentd monitoring-execd monitoring-modulesd monitoring-logcollector monitoring-syscheckd"

# State tracking
declare -A restart_counts
declare -A last_restart_time
declare -A process_down_time

# Logging function with dual output
log() {
    local level="$1"
    local message="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local log_entry="[$timestamp] [$level] [WATCHDOG] $message"
    
    echo "$log_entry" | tee -a "$WATCHDOG_LOG" >> "$LOG_FILE"
    
    # Also log to systemd journal
    case "$level" in
        "ERROR"|"CRITICAL")
            echo "$log_entry" >&2
            ;;
        *)
            echo "$log_entry"
            ;;
    esac
}

# Initialize restart tracking
init_tracking() {
    for process in $CRITICAL_PROCESSES; do
        restart_counts["$process"]=0
        last_restart_time["$process"]=0
        process_down_time["$process"]=0
    done
}

# Check if a process is running
is_process_running() {
    local process_name="$1"
    local binary_name
    
    # Convert monitoring process names to actual binary names
    case "$process_name" in
        "monitoring-agentd") binary_name="monitoring-agentd" ;;
        "monitoring-execd") binary_name="monitoring-execd" ;;
        "monitoring-modulesd") binary_name="monitoring-modulesd" ;;
        "monitoring-logcollector") binary_name="monitoring-logcollector" ;;
        "monitoring-syscheckd") binary_name="monitoring-syscheckd" ;;
        *) binary_name="$process_name" ;;
    esac
    
    # Check PID file first
    local pid_pattern="${PID_DIR}/${process_name}-*.pid"
    if compgen -G "$pid_pattern" > /dev/null 2>&1; then
        local pid_file=$(ls $pid_pattern 2>/dev/null | head -1)
        if [[ -f "$pid_file" ]]; then
            local pid=$(cat "$pid_file" 2>/dev/null || echo "")
            if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
                return 0  # Process is running
            fi
        fi
    fi
    
    # Fallback to process name check
    if pgrep -f "$binary_name" > /dev/null 2>&1; then
        return 0  # Process is running
    fi
    
    return 1  # Process is not running
}

# Check system health indicators
check_system_health() {
    local errors=0
    
    # Check disk space
    local disk_usage=$(df "${AGENT_HOME}" | awk 'NR==2 {print $5}' | sed 's/%//')
    if [[ $disk_usage -gt 95 ]]; then
        log "ERROR" "Disk usage critical: ${disk_usage}%"
        errors=$((errors + 1))
    elif [[ $disk_usage -gt 85 ]]; then
        log "WARN" "Disk usage high: ${disk_usage}%"
    fi
    
    # Check memory usage
    local mem_usage=$(free | awk '/^Mem:/ {printf "%.0f", $3/$2 * 100}')
    if [[ $mem_usage -gt 95 ]]; then
        log "ERROR" "Memory usage critical: ${mem_usage}%"
        errors=$((errors + 1))
    fi
    
    # Check configuration file
    if [[ ! -f "$CONFIG_FILE" ]]; then
        log "ERROR" "Configuration file missing: $CONFIG_FILE"
        errors=$((errors + 1))
    fi
    
    # Check log file rotation needed
    if [[ -f "$LOG_FILE" ]]; then
        local log_size=$(stat -f%z "$LOG_FILE" 2>/dev/null || stat -c%s "$LOG_FILE" 2>/dev/null || echo 0)
        if [[ $log_size -gt 104857600 ]]; then  # 100MB
            log "WARN" "Log file size large: $((log_size / 1024 / 1024))MB"
        fi
    fi
    
    return $errors
}

# Restart a specific process
restart_process() {
    local process_name="$1"
    local current_time=$(date +%s)
    
    # Check cooldown period
    local last_restart=${last_restart_time["$process_name"]}
    if [[ $((current_time - last_restart)) -lt $RESTART_COOLDOWN ]]; then
        log "WARN" "Process $process_name in cooldown period, skipping restart"
        return 1
    fi
    
    # Check restart limit
    local restart_count=${restart_counts["$process_name"]}
    if [[ $restart_count -ge $MAX_RESTART_ATTEMPTS ]]; then
        log "ERROR" "Process $process_name exceeded maximum restart attempts ($MAX_RESTART_ATTEMPTS)"
        return 1
    fi
    
    log "INFO" "Attempting to restart process: $process_name (attempt $((restart_count + 1)))"
    
    # Try to restart the individual process
    if "$CONTROL_SCRIPT" restart-process "$process_name" 2>&1 | while read -r line; do
        log "DEBUG" "Restart output: $line"
    done; then
        # Wait a bit and check if it started
        sleep 5
        if is_process_running "$process_name"; then
            log "INFO" "Successfully restarted process: $process_name"
            restart_counts["$process_name"]=$((restart_count + 1))
            last_restart_time["$process_name"]=$current_time
            process_down_time["$process_name"]=0
            return 0
        else
            log "ERROR" "Failed to restart process: $process_name"
            return 1
        fi
    else
        log "ERROR" "Restart command failed for process: $process_name"
        return 1
    fi
}

# Handle critical system failure
handle_critical_failure() {
    log "CRITICAL" "Multiple critical processes down - attempting full agent restart"
    
    # Try full agent restart
    if "$CONTROL_SCRIPT" restart 2>&1 | while read -r line; do
        log "DEBUG" "Full restart output: $line"
    done; then
        log "INFO" "Full agent restart initiated"
        sleep 10  # Give time for restart
        
        # Reset all counters after full restart
        init_tracking
    else
        log "CRITICAL" "Full agent restart failed - system may require manual intervention"
        
        # Send critical alert if configured
        if command -v systemd-notify >/dev/null 2>&1; then
            systemd-notify --status="CRITICAL: Agent restart failed"
        fi
    fi
}

# Generate health report
generate_health_report() {
    local report_file="${AGENT_HOME}/logs/health-report-$(date +%Y%m%d-%H%M%S).log"
    
    {
        echo "=== Monitoring Agent Health Report ==="
        echo "Generated: $(date)"
        echo "Uptime: $(uptime)"
        echo ""
        
        echo "=== Process Status ==="
        for process in $CRITICAL_PROCESSES; do
            if is_process_running "$process"; then
                echo "✓ $process: RUNNING"
            else
                echo "✗ $process: DOWN (restarts: ${restart_counts["$process"]})"
            fi
        done
        echo ""
        
        echo "=== System Resources ==="
        echo "Disk Usage: $(df "${AGENT_HOME}" | awk 'NR==2 {print $5}')"
        echo "Memory Usage: $(free -h | awk '/^Mem:/ {print $3"/"$2}')"
        echo "Load Average: $(uptime | awk -F'load average:' '{print $2}')"
        echo ""
        
        echo "=== Recent Logs ==="
        tail -20 "$LOG_FILE" 2>/dev/null || echo "No recent logs available"
        
    } > "$report_file"
    
    log "INFO" "Health report generated: $report_file"
}

# Main monitoring loop
main_loop() {
    log "INFO" "Monitoring Agent Watchdog started"
    log "INFO" "Monitoring processes: $CRITICAL_PROCESSES"
    log "INFO" "Check interval: ${CHECK_INTERVAL}s"
    
    local consecutive_failures=0
    local last_health_report=0
    
    while true; do
        local current_time=$(date +%s)
        local down_processes=0
        local critical_down=0
        
        # Check each critical process
        for process in $CRITICAL_PROCESSES; do
            if ! is_process_running "$process"; then
                down_processes=$((down_processes + 1))
                
                # Track how long it's been down
                if [[ ${process_down_time["$process"]} -eq 0 ]]; then
                    process_down_time["$process"]=$current_time
                    log "WARN" "Process $process detected as down"
                fi
                
                # Critical processes require immediate attention
                if [[ "$process" == "monitoring-agentd" ]] || [[ "$process" == "monitoring-execd" ]]; then
                    critical_down=$((critical_down + 1))
                fi
                
                # Try to restart if down for more than 30 seconds
                local down_duration=$((current_time - process_down_time["$process"]))
                if [[ $down_duration -gt 30 ]]; then
                    restart_process "$process"
                fi
            else
                # Reset down time if process is running
                if [[ ${process_down_time["$process"]} -ne 0 ]]; then
                    local down_duration=$((current_time - process_down_time["$process"]))
                    log "INFO" "Process $process recovered (was down for ${down_duration}s)"
                    process_down_time["$process"]=0
                fi
            fi
        done
        
        # Handle critical situations
        if [[ $critical_down -gt 0 ]] && [[ $down_processes -gt 2 ]]; then
            consecutive_failures=$((consecutive_failures + 1))
            log "ERROR" "Critical failure detected: $critical_down critical processes down, $down_processes total"
            
            if [[ $consecutive_failures -ge 3 ]]; then
                handle_critical_failure
                consecutive_failures=0
            fi
        else
            consecutive_failures=0
        fi
        
        # Periodic system health check
        if [[ $((current_time % 300)) -eq 0 ]]; then  # Every 5 minutes
            check_system_health
        fi
        
        # Generate health report every hour
        if [[ $((current_time - last_health_report)) -gt 3600 ]]; then
            generate_health_report
            last_health_report=$current_time
        fi
        
        # Reset restart counters daily
        if [[ $(date +%H%M) == "0000" ]]; then
            log "INFO" "Daily restart counter reset"
            init_tracking
        fi
        
        # Wait before next check
        sleep $CHECK_INTERVAL
    done
}

# Signal handlers
cleanup() {
    log "INFO" "Monitoring Agent Watchdog stopping"
    exit 0
}

trap cleanup TERM INT

# Ensure required directories exist
mkdir -p "$(dirname "$WATCHDOG_LOG")" 2>/dev/null || true

# Initialize tracking
init_tracking

# Start main loop
main_loop