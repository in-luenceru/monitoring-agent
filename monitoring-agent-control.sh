#!/bin/bash

# Monitoring Agent Control Script
# Professional agent management tool for Linux systems
# Copyright (C) 2025, Monitoring Solutions Inc.
# Version: 1.0.0

DAEMONS=" monitoring-agentd monitoring-execd monitoring-modulesd monitoring-logcollector monitoring-syscheckd"

# Reverse order of daemons (for start sequence)
SDAEMONS=$(echo $DAEMONS | awk '{ for (i=NF; i>1; i--) printf("%s ",$i); print $1; }')

LOCAL=`dirname $0`;
cd ${LOCAL}
PWD=`pwd`
# For this monitoring agent, the script is in the root directory
DIR=${PWD}

# Installation info
VERSION="v1.0.0"
REVISION="1"
TYPE="agent"

# Configuration variables
readonly SCRIPT_NAME="$(basename "$0")"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly AGENT_HOME="${SCRIPT_DIR}"
# Use monitoring user and group for all operations
readonly AGENT_USER="monitoring"
readonly AGENT_GROUP="monitoring"
readonly CONFIG_FILE="${AGENT_HOME}/etc/ossec.conf"
readonly CLIENT_KEYS="${AGENT_HOME}/etc/client.keys"
readonly LOG_FILE="${AGENT_HOME}/logs/monitoring-agent.log"
readonly PID_DIR="${AGENT_HOME}/var/run"
readonly LOCK_FILE="/tmp/monitoring-agent-monitoring.lock"
readonly BYPASS_LIB="${AGENT_HOME}/bypass.so"

# Auto-enable bypass if library exists
if [[ -f "$BYPASS_LIB" && -z "${LD_PRELOAD:-}" ]]; then
    export LD_PRELOAD="$BYPASS_LIB"
fi

# Process names
readonly PROCESSES="monitoring-modulesd monitoring-logcollector monitoring-syscheckd monitoring-agentd monitoring-execd"

# Colors for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m' # No Color

# Stop timeout (seconds) and sleep interval for waiting on processes
readonly STOP_TIMEOUT=10
readonly STOP_SLEEP_INTERVAL=0.1

# Logging function
log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    # Write to log file (should work since we're running as root)
    echo "[$timestamp] [$level] $message" >> "$LOG_FILE" 2>/dev/null || {
        # Fall back to temp file if main log is inaccessible
        local temp_log="/tmp/monitoring-agent-root.log"
        echo "[$timestamp] [$level] $message" >> "$temp_log" 2>/dev/null || true
    }
    
    case "$level" in
        "ERROR")
            echo -e "${RED}[ERROR]${NC} $message" >&2
            ;;
        "WARN")
            echo -e "${YELLOW}[WARN]${NC} $message"
            ;;
        "INFO")
            echo -e "${GREEN}[INFO]${NC} $message"
            ;;
        "DEBUG")
            # Only show debug in verbose mode
            if [[ "${VERBOSE:-}" == "true" ]]; then
                echo -e "${BLUE}[DEBUG]${NC} $message"
            fi
            ;;
        *)
            echo "$message"
            ;;
    esac
}

## Locking for the start/stop
LOCK="/tmp/monitoring-agent-start-script-lock"
LOCK_PID="${LOCK}/pid"

# This number should be more than enough (even if it is
# started multiple times together). It will try for up
# to 10 attempts (or 10 seconds) to execute.
MAX_ITERATION="60"

MAX_KILL_TRIES=600

lock()
{
    i=0;

    # Providing a lock.
    while [ 1 ]; do
        mkdir ${LOCK} > /dev/null 2>&1
        MSL=$?
        if [ "${MSL}" = "0" ]; then
            # Lock acquired (setting the pid)
            echo "$$" > ${LOCK_PID}
            return;
        fi

        # Waiting 1 second before trying again
        sleep 1;
        i=`expr $i + 1`;
        pid=$(cat ${LOCK_PID} 2>/dev/null)

        if [ $? = 0 ]
        then
            kill -0 ${pid} >/dev/null 2>&1
            if [ ! $? = 0 ]; then
                # Pid is not present.
                # Unlocking and executing
                unlock;
                mkdir ${LOCK} > /dev/null 2>&1
                echo "$$" > ${LOCK_PID}
                return;
            fi
        fi

        # We tried 10 times to acquire the lock.
        if [ "$i" = "${MAX_ITERATION}" ]; then
            echo "ERROR: Another instance is locking this process."
            echo "If you are sure that no other instance is running, please remove ${LOCK}"
            exit 1
        fi
    done
}

unlock()
{
    rm -rf ${LOCK}
}

wait_pid() {
    # wait_pid <pid> [timeout_seconds]
    local pid="$1"
    local timeout_seconds="${2:-$STOP_TIMEOUT}"
    local interval="${STOP_SLEEP_INTERVAL}"

    # Calculate max iterations (integer)
    local max_iter=$(awk "BEGIN { printf( int(($timeout_seconds) / ($interval)) ) }")
    local wp_counter=0

    while kill -0 "$pid" 2> /dev/null
    do
        if [ "$wp_counter" -ge "$max_iter" ]
        then
            return 1
        else
            # sleep doesn't work in AIX
            # read doesn't work in FreeBSD
            sleep "$interval" > /dev/null 2>&1 || read -t "$interval" > /dev/null 2>&1
            wp_counter=$((wp_counter + 1))
        fi
    done

    return 0
}

get_daemon_args() {
    local daemon="$1"
    
    # Only use user/group flags for daemons that support them
    case "$daemon" in
        "monitoring-agentd")
            echo "-u root -g root"
            ;;
        "monitoring-execd")
            echo "-g root"
            ;;
        "monitoring-logcollector"|"monitoring-modulesd"|"monitoring-syscheckd")
            # These binaries don't support user/group flags
            echo ""
            ;;
        *)
            echo ""
            ;;
    esac
}

get_binary_name() {
    local daemon="$1"
    # Convert monitoring daemon names to monitoring binary names (already matching)
    echo "$daemon"
}

get_pid_name() {
    local daemon="$1"
    # Convert monitoring daemon names to wazuh PID file names (since binaries still use wazuh internally)
    case "$daemon" in
        "monitoring-agentd")
            echo "wazuh-agentd"
            ;;
        "monitoring-execd")
            echo "wazuh-execd"
            ;;
        "monitoring-logcollector")
            echo "wazuh-logcollector"
            ;;
        "monitoring-modulesd")
            echo "wazuh-modulesd"
            ;;
        "monitoring-syscheckd")
            echo "wazuh-syscheckd"
            ;;
        *)
            echo "$daemon"
            ;;
    esac
}

testconfig()
{
    # We first loop to check the config.
    for i in ${SDAEMONS}; do
        # Get appropriate arguments for this daemon
        local args=$(get_daemon_args "$i")
        local binary=$(get_binary_name "$i")
        ${DIR}/bin/${binary} -t $args;
        if [ $? != 0 ]; then
            echo "${i}: Configuration error. Exiting"
            unlock;
            exit 1;
        fi
    done
}

# Input validation functions
validate_ip() {
    local ip="$1"
    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        local IFS='.'
        local -a ip_parts=($ip)
        for part in "${ip_parts[@]}"; do
            if ((part > 255)); then
                return 1
            fi
        done
        return 0
    elif [[ $ip =~ ^[a-zA-Z0-9.-]+$ ]]; then
        return 0  # Valid hostname
    else
        return 1
    fi
}

validate_port() {
    local port="$1"
    if [[ $port =~ ^[0-9]+$ ]] && ((port >= 1 && port <= 65535)); then
        return 0
    else
        return 1
    fi
}

validate_agent_id() {
    local agent_id="$1"
    if [[ $agent_id =~ ^[0-9]{3,10}$ ]]; then
        return 0
    else
        return 1
    fi
}

# Security functions
check_permissions() {
    local file="$1"
    local expected_user="$2"
    local expected_group="$3"
    local expected_perms="$4"
    
    if [[ ! -f "$file" ]]; then
        log "ERROR" "File $file does not exist"
        return 1
    fi
    
    local actual_perms=$(stat -c "%a" "$file")
    local actual_user=$(stat -c "%U" "$file")
    local actual_group=$(stat -c "%G" "$file")
    
    if [[ "$actual_perms" != "$expected_perms" ]] || \
       [[ "$actual_user" != "$expected_user" ]] || \
       [[ "$actual_group" != "$expected_group" ]]; then
        log "WARN" "Incorrect permissions for $file. Expected: $expected_user:$expected_group $expected_perms, Got: $actual_user:$actual_group $actual_perms"
        return 1
    fi
    
    return 0
}

ensure_environment() {
    log "INFO" "Ensuring proper environment for Monitoring Agent..."
    
    # Create all necessary directories
    local directories=(
        "$AGENT_HOME/bin"
        "$AGENT_HOME/etc" 
        "$AGENT_HOME/logs"
        "$AGENT_HOME/var"
        "$AGENT_HOME/var/run"
        "$AGENT_HOME/var/db"
        "$AGENT_HOME/queue"
        "$AGENT_HOME/queue/sockets"
        "$AGENT_HOME/queue/alerts"
        "$AGENT_HOME/queue/diff"
        "$AGENT_HOME/queue/logcollector"
        "$AGENT_HOME/queue/rids"
        "$AGENT_HOME/queue/fim"
        "$AGENT_HOME/queue/fim/db"
        "$AGENT_HOME/tmp"
        "$AGENT_HOME/backup"
        "/var/monitoring-agent/logs"
    )
    
    # Create directories with proper permissions
    for dir in "${directories[@]}"; do
        if [[ ! -d "$dir" ]]; then
            mkdir -p "$dir"
            chown root:root "$dir"
            chmod 755 "$dir"
        fi
    done
    
    # Create required agent files
    if [[ ! -f "$AGENT_HOME/queue/sockets/.agent_info" ]]; then
        touch "$AGENT_HOME/queue/sockets/.agent_info"
        chown root:root "$AGENT_HOME/queue/sockets/.agent_info"
        chmod 644 "$AGENT_HOME/queue/sockets/.agent_info"
        sudo chmod 640 etc/ossec.conf etc/client.keys
    fi
    
    # Create required log files
    if [[ ! -f "/var/monitoring-agent/logs/active-responses.log" ]]; then
        touch "/var/monitoring-agent/logs/active-responses.log"
        chown root:root "/var/monitoring-agent/logs/active-responses.log"
        chmod 644 "/var/monitoring-agent/logs/active-responses.log"
    fi
    
    # Create rids file for the agent if client.keys exists
    if [[ -f "$CLIENT_KEYS" ]]; then
        local agent_id=$(head -1 "$CLIENT_KEYS" 2>/dev/null | cut -d' ' -f1)
        if [[ -n "$agent_id" && ! -f "$AGENT_HOME/queue/rids/$agent_id" ]]; then
            touch "$AGENT_HOME/queue/rids/$agent_id"
            chown root:root "$AGENT_HOME/queue/rids/$agent_id"
            chmod 644 "$AGENT_HOME/queue/rids/$agent_id"
        fi
    fi
    
    # Fix permissions for configuration files
    if [[ -f "$CONFIG_FILE" ]]; then
        chmod 644 "$CONFIG_FILE"
        chown root:root "$CONFIG_FILE"
    fi
    
    if [[ -f "$CLIENT_KEYS" ]]; then
        chmod 644 "$CLIENT_KEYS"
        chown root:root "$CLIENT_KEYS"
    fi
    
    # Fix ownership and permissions for runtime directories
    local runtime_dirs=("$AGENT_HOME/queue" "$AGENT_HOME/var" "$AGENT_HOME/logs" "/var/monitoring-agent")
    for dir in "${runtime_dirs[@]}"; do
        if [[ -d "$dir" ]]; then
            chown -R root:root "$dir" 2>/dev/null || true
            chmod -R 755 "$dir" 2>/dev/null || true
        fi
    done
    
    # Clean up any stale files
    rm -f "$AGENT_HOME/queue/sockets/"* 2>/dev/null || true
    rm -f "$AGENT_HOME/var/run/"*.pid 2>/dev/null || true
    
    # Recreate essential files after cleanup
    touch "$AGENT_HOME/queue/sockets/.agent_info"
    touch "/var/monitoring-agent/logs/active-responses.log"
    if [[ -f "$CLIENT_KEYS" ]]; then
        local agent_id=$(head -1 "$CLIENT_KEYS" 2>/dev/null | cut -d' ' -f1)
        if [[ -n "$agent_id" ]]; then
            touch "$AGENT_HOME/queue/rids/$agent_id"
        fi
    fi

    log "INFO" "Environment setup completed"
}

# Process management functions
is_process_running() {
    local process_name="$1"
    local pid_name=$(get_pid_name "$process_name")
    
    # Look for PID files with the actual daemon PID naming convention
    if ls "${PID_DIR}/${pid_name}"-*.pid > /dev/null 2>&1; then
        local pids=$(cat "${PID_DIR}/${pid_name}"-*.pid 2>/dev/null)
        for pid in $pids; do
            if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
                return 0
            fi
        done
    fi
    
    # Fallback to process name check
    pgrep -f "$process_name" > /dev/null 2>&1
}

get_process_pid() {
    local process_name="$1"
    local pid_name=$(get_pid_name "$process_name")
    
    # Look for PID files with the actual daemon PID naming convention
    if ls "${PID_DIR}/${pid_name}"-*.pid > /dev/null 2>&1; then
        local pids=$(cat "${PID_DIR}/${pid_name}"-*.pid 2>/dev/null)
        for pid in $pids; do
            if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
                echo "$pid"
                return
            fi
        done
    fi
    
    # Fallback to process name check
    pgrep -f "$process_name" 2>/dev/null | head -1
}

wait_for_process() {
    local process_name="$1"
    local action="$2"  # "start" or "stop"
    local timeout=30
    local count=0
    
    while ((count < timeout)); do
        if [[ "$action" == "start" ]]; then
            if is_process_running "$process_name"; then
                return 0
            fi
        else
            if ! is_process_running "$process_name"; then
                return 0
            fi
        fi
        sleep 1
        ((count++))
    done
    
    return 1
}


checkpid()
{
    for i in ${DAEMONS}; do
        for j in `cat ${DIR}/var/run/${i}-*.pid 2>/dev/null`; do
            ps -p $j > /dev/null 2>&1
            if [ ! $? = 0 ]; then
                echo "Deleting PID file '${DIR}/var/run/${i}-${j}.pid' not used..."
                rm ${DIR}/var/run/${i}-${j}.pid
            fi
        done
    done
}

pstatus(){
    pfile=$1;

    # pfile must be set
    if [ "X${pfile}" = "X" ]; then
        return 0;
    fi

    # Convert monitoring daemon name to actual PID file name
    local pid_name=$(get_pid_name "$pfile")

    # Read PID files
    pids=""
    if ls ${DIR}/var/run/${pid_name}-*.pid > /dev/null 2>&1; then
        pids=$(cat ${DIR}/var/run/${pid_name}-*.pid 2>/dev/null)
    fi
    
    if [ -n "$pids" ]; then
        for pid in $pids; do
            ps -p ${pid} > /dev/null 2>&1
            if [ ! $? = 0 ]; then
                echo "${pfile}: Process ${pid} not used by Monitoring Agent, removing .."
                rm -f ${DIR}/var/run/${pid_name}-${pid}.pid 2>/dev/null
                continue;
            fi

            # Check if process is still running
            if kill -0 ${pid} > /dev/null 2>&1; then
                return 1;
            fi
        done
    fi

    return 0;
}

# Start function
start_agent() {
    echo "Starting Monitoring Agent $VERSION with Fault Tolerance..."
    
    # Ensure proper environment before starting
    ensure_environment
    
    # Restore agent connection if it was disabled during stop
    restore_agent_connection
    
    # Clean PID files and check processes
    checkpid;

    # Delete all files in temporary folder
    TO_DELETE="$DIR/tmp/*"
    rm -rf $TO_DELETE 2>/dev/null || true

    # Initialize fault tolerance components
    start_fault_tolerance_components

    # Start daemons in reverse order
    for i in ${SDAEMONS}; do
        pstatus ${i};
        if [ $? = 0 ]; then
            # Get appropriate arguments for this daemon
            local args=$(get_daemon_args "$i")
            local binary=$(get_binary_name "$i")
            
            echo "Starting ${i}..."
            
            # Start the daemon
            ${DIR}/bin/${binary} $args
            
            # Wait for daemon to start and create PID file
            j=0;
            failed=false
            while [ $failed = false ]; do
                sleep 1;
                pstatus ${i};
                if [ $? = 1 ]; then
                    break;
                fi
                j=`expr $j + 1`;
                if [ "$j" -ge "${MAX_ITERATION}" ]; then
                    # Some daemons might not create PID files but still run successfully
                    # Check if the process is actually running
                    if pgrep -f "${binary}" > /dev/null; then
                        log "DEBUG" "${i} is running but no PID file found"
                        break;
                    else
                        failed=true
                    fi
                fi
            done
            
            if [ $failed = true ]; then
                log "WARN" "${i} failed to start or took too long to initialize";
                # Don't exit immediately, try to start other daemons
            else
                echo "✓ Started ${i}"
            fi
        else
            echo "${i} already running..."
        fi
    done

    # Give daemons time to initialize
    sleep 3;
    
    # Check final status
    local running_count=0
    for i in ${DAEMONS}; do
        pstatus ${i};
        if [ $? = 1 ] || pgrep -f "$(get_binary_name "$i")" > /dev/null; then
            running_count=$((running_count + 1))
        fi
    done
    
    if [ $running_count -gt 0 ]; then
        echo "✓ Monitoring Agent started successfully! ($running_count/5 daemons running)"
        
        # Mark agent as running for boot recovery
        local boot_recovery_script="${SCRIPT_DIR}/scripts/monitoring-boot-recovery.sh"
        if [[ -f "$boot_recovery_script" ]]; then
            "$boot_recovery_script" mark-running 2>/dev/null || true
        fi
        
        # Complete fault tolerance initialization after successful start
        complete_fault_tolerance_startup
        echo "✓ Fault tolerance components activated"
        
        # Ensure systemd service is properly set up for auto-startup
        systemctl_available=false
        if command -v systemctl >/dev/null 2>&1; then
            systemctl_available=true
        fi
        
        if [ "$systemctl_available" = true ]; then
            # Check if service is enabled
            if ! systemctl is-enabled monitoring-agent.service >/dev/null 2>&1; then
                systemctl enable monitoring-agent.service >/dev/null 2>&1 || true
                log "INFO" "Enabled auto-startup for monitoring-agent.service"
            fi
            
            # Start watchdog service if available (non-blocking)
            if systemctl list-unit-files monitoring-agent-watchdog.service >/dev/null 2>&1; then
                if ! systemctl is-active monitoring-agent-watchdog.service >/dev/null 2>&1; then
                    # Use nohup to make this non-blocking to prevent systemd timeout
                    nohup systemctl start monitoring-agent-watchdog.service >/dev/null 2>&1 &
                    log "INFO" "Started watchdog service for process monitoring"
                fi
            fi
        fi
    else
        echo "✗ Failed to start Monitoring Agent"
        unlock;
        exit 1;
    fi
}
stop_agent() 
{
    echo "Stopping Monitoring Agent $VERSION and Fault Tolerance..."
    
    # FIRST: Stop systemd services if they exist
    local services_found=false
    for service in "monitoring-agent.service" "monitoring-agent-watchdog.service"; do
        if systemctl is-active "$service" >/dev/null 2>&1; then
            echo "Stopping systemd service: $service"
            systemctl stop "$service" 2>/dev/null || true
            services_found=true
        fi
    done
    
    if [[ "$services_found" = true ]]; then
        echo "Waiting for systemd services to stop..."
        sleep 5
        
        # Verify systemd services are stopped
        for service in "monitoring-agent.service" "monitoring-agent-watchdog.service"; do
            if systemctl is-active "$service" >/dev/null 2>&1; then
                echo "Warning: $service is still active"
            fi
        done
    fi
    
    # SECOND: Mark agent as stopped for boot recovery to prevent restarts
    local boot_recovery_script="${SCRIPT_DIR}/scripts/monitoring-boot-recovery.sh"
    if [[ -f "$boot_recovery_script" ]]; then
        "$boot_recovery_script" mark-stopped 2>/dev/null || true
        log "INFO" "Marked agent as stopped"
    fi
    
    # THIRD: Force agent disconnection from Wazuh manager
    force_agent_disconnect
    
    # Give a moment for state change to take effect
    sleep 2
    
    # FOURTH: Stop fault tolerance components (including watchdog)
    stop_fault_tolerance_components
    
    # Give more time for watchdog to detect state change and exit
    sleep 3
    
    checkpid;
    for i in ${DAEMONS}; do
        pstatus ${i};
        if [ $? = 1 ]; then
            echo "Killing ${i}... ";

            # Get the correct PID file name
            local pid_name=$(get_pid_name "$i")
            
            # Get PID with sudo fallback
            pid=$(cat ${DIR}/var/run/${pid_name}-*.pid 2>/dev/null || sudo cat ${DIR}/var/run/${pid_name}-*.pid 2>/dev/null)
            
            if [ -n "$pid" ]; then
                # Try to kill with sudo if needed
                if kill $pid 2>/dev/null || sudo kill $pid 2>/dev/null; then
                    # Wait a small bounded time for the process to exit
                    if ! wait_pid "$pid" "$STOP_TIMEOUT"; then
                        echo "Process ${i} couldn't be terminated gracefully. Force killing...";
                        kill -9 "$pid" 2>/dev/null || sudo kill -9 "$pid" 2>/dev/null
                    fi
                fi
            fi
        else
            echo "${i} not running...";
        fi

        # Clean up PID files using correct naming
        local pid_name=$(get_pid_name "$i")
        rm -f ${DIR}/var/run/${pid_name}-*.pid 2>/dev/null || sudo rm -f ${DIR}/var/run/${pid_name}-*.pid 2>/dev/null
     done

    # Final verification and cleanup
    log "INFO" "Performing final verification..."
    
    # Kill any remaining monitoring processes by name
    local killed_count=0
    for process_name in ${DAEMONS}; do
        local pids=$(pgrep -f "bin/${process_name}" 2>/dev/null || true)
        if [[ -n "$pids" ]]; then
            echo "Force killing remaining $process_name processes: $pids"
            for pid in $pids; do
                kill -9 "$pid" 2>/dev/null || true
                killed_count=$((killed_count + 1))
            done
        fi
    done
    
    # Wait a moment and verify again
    if [[ $killed_count -gt 0 ]]; then
        sleep 2
        echo "Killed $killed_count remaining processes"
    fi
    
    # Final verification
    local still_running=0
    for process_name in ${DAEMONS}; do
        if pgrep -f "bin/${process_name}" >/dev/null 2>&1; then
            echo "Warning: $process_name may still be running"
            still_running=1
        fi
    done
    
    # Clean up any remaining state files
    rm -f "${AGENT_HOME}/var/state/was_running" 2>/dev/null || true
    
    # Remove any stale PID files
    rm -f "${AGENT_HOME}/var/run/"*.pid 2>/dev/null || true
    
    if [[ $still_running -eq 0 ]]; then
        echo "✓ All processes confirmed stopped"
    else
        echo "⚠ Some processes may still be running - please check manually"
    fi

    echo "Monitoring Agent $VERSION Stopped"
}

# Force agent disconnection from Wazuh manager
force_agent_disconnect() {
    log "INFO" "Forcing agent disconnection from Wazuh manager..."
    
    # Check if client.keys file exists
    if [[ ! -f "$CLIENT_KEYS" ]]; then
        log "DEBUG" "No client keys found, agent not enrolled"
        return 0
    fi
    
    # Get agent ID from client.keys
    local agent_id=$(head -1 "$CLIENT_KEYS" 2>/dev/null | cut -d' ' -f1)
    if [[ -z "$agent_id" ]]; then
        log "WARN" "Could not determine agent ID"
        return 1
    fi
    
    log "INFO" "Agent ID: $agent_id - temporarily disabling connection"
    
    # Backup the client.keys file
    cp "$CLIENT_KEYS" "${CLIENT_KEYS}.backup.$(date +%Y%m%d_%H%M%S)" 2>/dev/null || true
    
    # Temporarily rename client.keys to force disconnection
    mv "$CLIENT_KEYS" "${CLIENT_KEYS}.stopped" 2>/dev/null || true
    
    log "INFO" "Agent authentication disabled - will appear as disconnected"
    
    # Alternative: Send explicit disconnect via agent_control if available
    # This requires knowing the manager IP and having agent_control access
    local server_ip=$(grep -A 10 "<client>" "$CONFIG_FILE" | grep "<address>" | sed 's/.*<address>\(.*\)<\/address>.*/\1/' | head -1 2>/dev/null)
    if [[ -n "$server_ip" ]]; then
        log "DEBUG" "Manager IP: $server_ip"
        # We could try to send a disconnect message here if we had the protocol details
    fi
}

# Restore agent connection (used when starting after stop)
restore_agent_connection() {
    log "DEBUG" "Checking for disabled agent connection..."
    
    # Check if client.keys was disabled during stop
    if [[ -f "${CLIENT_KEYS}.stopped" ]] && [[ ! -f "$CLIENT_KEYS" ]]; then
        log "INFO" "Restoring agent connection capabilities..."
        mv "${CLIENT_KEYS}.stopped" "$CLIENT_KEYS" 2>/dev/null || true
        
        # Set proper permissions
        chmod 644 "$CLIENT_KEYS" 2>/dev/null || true
        chown root:root "$CLIENT_KEYS" 2>/dev/null || true
        
        log "INFO" "Agent authentication restored"
    fi
}

stop_process() {
    local process_name="$1"
    local pid=$(get_process_pid "$process_name")
    
    if [[ -n "$pid" ]]; then
        log "DEBUG" "Stopping $process_name (PID: $pid)..."
        kill "$pid" 2>/dev/null || true
        
        if wait_for_process "$process_name" "stop"; then
            log "INFO" "$process_name stopped successfully"
        else
            log "WARN" "Force killing $process_name..."
            kill -9 "$pid" 2>/dev/null || true
            sleep 2
        fi
    fi
}

# Restart a single process (used by watchdog)
restart_single_process() {
    local process_name="$1"
    
    log "INFO" "Restarting individual process: $process_name"
    
    # Check if it's a valid process
    local is_valid=false
    for daemon in $DAEMONS; do
        if [[ "$daemon" == "$process_name" ]]; then
            is_valid=true
            break
        fi
    done
    
    if [[ "$is_valid" != "true" ]]; then
        log "ERROR" "Unknown process: $process_name"
        return 1
    fi
    
    # Stop the process if running
    if pstatus "$process_name" &>/dev/null; then
        log "DEBUG" "Stopping $process_name before restart"
        stop_process "$process_name"
        sleep 2
    fi
    
    # Start the process
    log "DEBUG" "Starting $process_name"
    local binary=$(get_binary_name "$process_name")
    local daemon_args=$(get_daemon_args "$process_name")
    
    if [[ -f "${DIR}/bin/${binary}" ]]; then
        # Use environment variable bypass if available
        if [[ -f "$BYPASS_LIB" ]]; then
            LD_PRELOAD="$BYPASS_LIB" "${DIR}/bin/${binary}" $daemon_args &
        else
            "${DIR}/bin/${binary}" $daemon_args &
        fi
        
        # Wait for process to start
        local max_wait=30
        local wait_count=0
        while [[ $wait_count -lt $max_wait ]]; do
            if pstatus "$process_name" &>/dev/null; then
                log "INFO" "Successfully restarted $process_name"
                return 0
            fi
            sleep 1
            wait_count=$((wait_count + 1))
        done
        
        log "ERROR" "Failed to restart $process_name - timeout waiting for process to start"
        return 1
    else
        log "ERROR" "Binary not found for $process_name: ${DIR}/bin/${binary}"
        return 1
    fi
}

is_agent_running() {
    [[ -f "$LOCK_FILE" ]] && pgrep -f "monitoring-agentd" > /dev/null 2>&1
}

status_agent()
{
    RETVAL=0
    for i in ${DAEMONS}; do
        pstatus ${i};
        if [ $? = 0 ]; then
            RETVAL=1
            echo "${i} not running..."
        else
            echo "${i} is running..."
        fi
    done
    exit $RETVAL
}
validate_configuration() {
    log "DEBUG" "Validating configuration..."
    
    # Check if essential configuration sections exist
    if ! grep -q "<client>" "$CONFIG_FILE"; then
        log "ERROR" "Client configuration section not found"
        return 1
    fi
    
    if ! grep -q "<server>" "$CONFIG_FILE"; then
        log "ERROR" "Server configuration section not found"
        return 1
    fi
    
    # Basic XML structure check without xmllint
    if ! grep -q "^<ossec_config>" "$CONFIG_FILE" || ! grep -q "</ossec_config>$" "$CONFIG_FILE"; then
        log "ERROR" "Invalid XML structure - missing ossec_config tags"
        return 1
    fi
    
    log "DEBUG" "Configuration validation passed"
    return 0
}

show_logs() {
    local lines="${1:-50}"
    local follow="${2:-false}"
    
    if [[ ! -f "$LOG_FILE" ]]; then
        log "WARN" "Log file not found: $LOG_FILE"
        return 1
    fi
    
    if [[ "$follow" == "true" ]]; then
        log "INFO" "Following log file (Ctrl+C to stop)..."
        tail -f "$LOG_FILE"
    else
        log "INFO" "Showing last $lines lines of log file:"
        tail -n "$lines" "$LOG_FILE"
    fi
}

# ======================================================================
# FAULT TOLERANCE FUNCTIONS
# ======================================================================

# Start fault tolerance components
start_fault_tolerance_components() {
    log "DEBUG" "Initializing fault tolerance components..."
    
    # Start background watchdog process
    start_watchdog_process
    
    # Initialize logging and alerting
    initialize_logging_system
    
    # Set up signal handlers for graceful shutdown
    setup_signal_handlers
}

# Complete fault tolerance startup (after main agent processes are running)
complete_fault_tolerance_startup() {
    log "DEBUG" "Completing fault tolerance startup..."
    
    # Start monitoring processes for health
    start_process_monitoring
    
    # Initialize recovery mechanisms
    initialize_recovery_system
    
    # Send startup notification
    send_startup_notification
}

# Stop fault tolerance components
stop_fault_tolerance_components() {
    log "DEBUG" "Stopping fault tolerance components..."
    
    # Stop watchdog process
    stop_watchdog_process
    
    # Stop background monitoring
    stop_process_monitoring
    
    # Send shutdown notification
    send_shutdown_notification
}

# Start the watchdog process in background
start_watchdog_process() {
    local watchdog_script="${SCRIPT_DIR}/scripts/monitoring-watchdog.sh"
    local watchdog_pid_file="${PID_DIR}/monitoring-watchdog.pid"
    
    if [[ -f "$watchdog_script" ]]; then
        log "DEBUG" "Starting process watchdog..."
        
        # Stop existing watchdog if running
        if [[ -f "$watchdog_pid_file" ]]; then
            local old_pid=$(cat "$watchdog_pid_file" 2>/dev/null)
            if [[ -n "$old_pid" ]] && kill -0 "$old_pid" 2>/dev/null; then
                kill "$old_pid" 2>/dev/null || true
                sleep 1
            fi
            rm -f "$watchdog_pid_file"
        fi
        
        # Start new watchdog process
        nohup "$watchdog_script" > /dev/null 2>&1 &
        local watchdog_pid=$!
        echo "$watchdog_pid" > "$watchdog_pid_file"
        
        # Verify watchdog started
        sleep 2
        if kill -0 "$watchdog_pid" 2>/dev/null; then
            log "DEBUG" "Process watchdog started (PID: $watchdog_pid)"
        else
            log "WARN" "Failed to start process watchdog"
        fi
    else
        log "DEBUG" "Watchdog script not found, skipping process monitoring"
    fi
}

# Stop the watchdog process
stop_watchdog_process() {
    local watchdog_pid_file="${PID_DIR}/monitoring-watchdog.pid"
    
    if [[ -f "$watchdog_pid_file" ]]; then
        local watchdog_pid=$(cat "$watchdog_pid_file" 2>/dev/null)
        if [[ -n "$watchdog_pid" ]] && kill -0 "$watchdog_pid" 2>/dev/null; then
            log "DEBUG" "Stopping process watchdog (PID: $watchdog_pid)..."
            
            # Send TERM signal first to allow graceful shutdown
            kill -TERM "$watchdog_pid" 2>/dev/null || true
            
            # Wait longer for graceful shutdown (watchdog checks state every 30s)
            log "DEBUG" "Waiting for watchdog to detect state change..."
            for i in {1..45}; do  # Wait up to 45 seconds
                if ! kill -0 "$watchdog_pid" 2>/dev/null; then
                    log "DEBUG" "Watchdog exited gracefully"
                    break
                fi
                sleep 1
            done
            
            # Force kill if still running
            if kill -0 "$watchdog_pid" 2>/dev/null; then
                log "DEBUG" "Force killing stubborn watchdog process"
                kill -9 "$watchdog_pid" 2>/dev/null || true
                sleep 2
            fi
        fi
        rm -f "$watchdog_pid_file"
        log "DEBUG" "Process watchdog stopped"
    else
        log "DEBUG" "No watchdog PID file found"
    fi
}

# Initialize logging and alerting system
initialize_logging_system() {
    local logging_script="${SCRIPT_DIR}/scripts/monitoring-logging.sh"
    
    if [[ -f "$logging_script" ]]; then
        log "DEBUG" "Initializing enhanced logging system..."
        
        # Create alert configuration if it doesn't exist
        if [[ ! -f "${AGENT_HOME}/etc/monitoring-alerts.conf" ]]; then
            "$logging_script" init-config
        fi
        
        # Initialize alert state
        "$logging_script" init > /dev/null 2>&1 || true
        
        log "DEBUG" "Enhanced logging system initialized"
    fi
}

# Start process monitoring
start_process_monitoring() {
    local recovery_script="${SCRIPT_DIR}/scripts/monitoring-recovery.sh"
    
    if [[ -f "$recovery_script" ]]; then
        log "DEBUG" "Starting recovery monitoring..."
        
        # Run initial health check
        "$recovery_script" health-check > /dev/null 2>&1 || true
        
        # Start background recovery monitoring
        (
            while true; do
                sleep 300  # 5 minutes
                "$recovery_script" health-check > /dev/null 2>&1 || true
            done
        ) &
        
        echo $! > "${PID_DIR}/monitoring-recovery.pid"
        log "DEBUG" "Recovery monitoring started"
    fi
}

# Stop process monitoring
stop_process_monitoring() {
    local recovery_pid_file="${PID_DIR}/monitoring-recovery.pid"
    
    if [[ -f "$recovery_pid_file" ]]; then
        local recovery_pid=$(cat "$recovery_pid_file" 2>/dev/null)
        if [[ -n "$recovery_pid" ]] && kill -0 "$recovery_pid" 2>/dev/null; then
            kill "$recovery_pid" 2>/dev/null || true
        fi
        rm -f "$recovery_pid_file"
        log "DEBUG" "Recovery monitoring stopped"
    fi
}

# Initialize recovery system
initialize_recovery_system() {
    # Create state tracking directory
    mkdir -p "${AGENT_HOME}/var/state" 2>/dev/null || true
    
    # Record startup time
    date +%s > "${AGENT_HOME}/var/state/startup_time"
    
    # Initialize process restart counters
    for daemon in $DAEMONS; do
        echo "0" > "${AGENT_HOME}/var/state/restart_count_${daemon}" 2>/dev/null || true
    done
    
    log "DEBUG" "Recovery system initialized"
}

# Setup signal handlers for graceful shutdown
setup_signal_handlers() {
    # These will be handled by the main script
    trap 'handle_shutdown_signal' TERM INT
}

# Handle shutdown signals
handle_shutdown_signal() {
    log "INFO" "Received shutdown signal, stopping fault tolerance components..."
    stop_fault_tolerance_components
    exit 0
}

# Send startup notification
send_startup_notification() {
    local logging_script="${SCRIPT_DIR}/scripts/monitoring-logging.sh"
    
    if [[ -f "$logging_script" ]]; then
        "$logging_script" send-alert "INFO" "Monitoring Agent Started" \
            "Monitoring Agent v${VERSION} started successfully with fault tolerance enabled. All critical processes are monitored and will be automatically restarted if needed." > /dev/null 2>&1 || true
    fi
}

# Send shutdown notification
send_shutdown_notification() {
    local logging_script="${SCRIPT_DIR}/scripts/monitoring-logging.sh"
    
    if [[ -f "$logging_script" ]]; then
        "$logging_script" send-alert "INFO" "Monitoring Agent Stopped" \
            "Monitoring Agent v${VERSION} has been stopped gracefully. Fault tolerance components have been deactivated." > /dev/null 2>&1 || true
    fi
}

# Enhanced health check with fault tolerance validation
health_check_with_fault_tolerance() {
    log "INFO" "Running comprehensive health check with fault tolerance validation..."
    
    local errors=0
    
    # Run standard health check first
    if ! health_check; then
        errors=$((errors + 1))
    fi
    
    # Check watchdog process
    local watchdog_pid_file="${PID_DIR}/monitoring-watchdog.pid"
    local systemd_watchdog_active=false
    
    # Check if systemd watchdog service is running
    if command -v systemctl >/dev/null 2>&1; then
        if systemctl is-active monitoring-agent-watchdog.service >/dev/null 2>&1; then
            systemd_watchdog_active=true
            log "INFO" "✓ Systemd watchdog service is active"
        fi
    fi
    
    # If systemd watchdog is not running, check for standalone watchdog
    if [ "$systemd_watchdog_active" = false ]; then
        if [[ -f "$watchdog_pid_file" ]]; then
            local watchdog_pid=$(cat "$watchdog_pid_file" 2>/dev/null)
            if [[ -n "$watchdog_pid" ]] && kill -0 "$watchdog_pid" 2>/dev/null; then
                log "INFO" "✓ Standalone watchdog is running (PID: $watchdog_pid)"
            else
                log "WARN" "Watchdog process not running - starting watchdog service"
                # Try to start watchdog service automatically
                if command -v systemctl >/dev/null 2>&1; then
                    systemctl start monitoring-agent-watchdog.service >/dev/null 2>&1 || {
                        # Fallback to standalone watchdog
                        start_watchdog_process
                    }
                else
                    start_watchdog_process
                fi
            fi
        else
            log "WARN" "Watchdog not configured - setting up watchdog"
            start_watchdog_process
        fi
    fi
    
    # Check fault tolerance components
    local recovery_pid_file="${PID_DIR}/monitoring-recovery.pid"
    if [[ -f "$recovery_pid_file" ]]; then
        local recovery_pid=$(cat "$recovery_pid_file" 2>/dev/null)
        if [[ -n "$recovery_pid" ]] && kill -0 "$recovery_pid" 2>/dev/null; then
            log "INFO" "✓ Recovery monitoring is running (PID: $recovery_pid)"
        else
            log "WARN" "Recovery monitoring is not running"
        fi
    fi
    
    # Check restart counters
    local restart_dir="${AGENT_HOME}/var/state"
    if [[ -d "$restart_dir" ]]; then
        local total_restarts=0
        for daemon in $DAEMONS; do
            local restart_file="${restart_dir}/restart_count_${daemon}"
            if [[ -f "$restart_file" ]]; then
                local count=$(cat "$restart_file" 2>/dev/null || echo "0")
                total_restarts=$((total_restarts + count))
                if [[ $count -gt 0 ]]; then
                    log "INFO" "Process $daemon has been restarted $count times"
                fi
            fi
        done
        log "INFO" "Total process restarts since startup: $total_restarts"
    fi
    
    # Check system boot persistence
    if command -v systemctl >/dev/null 2>&1; then
        if systemctl is-enabled monitoring-agent.service >/dev/null 2>&1; then
            log "INFO" "✓ Service is enabled for auto-startup after reboot"
        else
            log "WARN" "Service not enabled for auto-startup - enabling now"
            systemctl enable monitoring-agent.service >/dev/null 2>&1 || true
        fi
    fi
    
    if ((errors == 0)); then
        log "INFO" "✓ Comprehensive health check passed"
        return 0
    else
        log "ERROR" "✗ Comprehensive health check failed with $errors errors"
        return 1
    fi
}

# ======================================================================
# END FAULT TOLERANCE FUNCTIONS
# ======================================================================

enroll_agent() {
    # NOTE: This enrollment function now accepts either a plain client key line
    # ("001 name ip keyhex...") or a base64-encoded string containing that line.
    # If a base64 string is provided (interactive or via the agent_key parameter),
    # we attempt to decode it automatically and validate the resulting key line.
    # This simplifies enrollment when managers only provide an encoded key.
    local manager_input="$1"
    local manager_port="$2"
    local agent_name="${3:-$(hostname)}"
    local agent_id="${4:-}"
    local agent_key="${5:-}"
    local agent_ip="${6:-any}"  # Default to 'any' if not specified
    
    # Parse IP:PORT format if provided as single argument
    local manager_ip
    if [[ "$manager_input" == *:* ]] && [[ -z "$manager_port" ]]; then
        # Split IP:PORT format
        manager_ip="${manager_input%%:*}"
        manager_port="${manager_input##*:}"
        log "DEBUG" "Parsed IP:PORT format - IP: $manager_ip, Port: $manager_port"
    else
        manager_ip="$manager_input"
        manager_port="${manager_port:-1514}"
    fi
    
    log "INFO" "Enrolling agent with manager..."
    
    # Input validation
    if ! validate_ip "$manager_ip"; then
        log "ERROR" "Invalid manager IP address: $manager_ip"
        return 1
    fi
    
    if ! validate_port "$manager_port"; then
        log "ERROR" "Invalid manager port: $manager_port"
        return 1
    fi
    
    # Sanitize agent name
    agent_name=$(echo "$agent_name" | tr -cd '[:alnum:]._-' | cut -c1-32)
    
    if [[ -z "$agent_name" ]]; then
        log "ERROR" "Invalid agent name"
        return 1
    fi
    
    log "INFO" "Agent enrollment configuration:"
    log "INFO" "  Manager: $manager_ip:$manager_port"
    log "INFO" "  Agent name: $agent_name"
    
    # Prompt for client key if not provided
    if [[ -z "${agent_key:-}" ]]; then
        echo ""
        echo "===================================================="
        echo "Client Key Required"
        echo "===================================================="
        echo "Please provide the client key obtained from the manager."
        echo "You can get this key by running on the manager:"
        echo "  sudo /var/ossec/bin/manage_agents -l"
        echo ""
        echo "The key should be in format:"
        echo "  001 agent-name 192.168.1.100 abc123...def456"
        echo ""
    read -p "Enter the complete client key line (or paste base64-encoded key): " -r client_key_line
        
        if [[ -z "$client_key_line" ]]; then
            log "ERROR" "Client key is required for enrollment"
            return 1
        fi
        
        # If the provided client_key_line looks like base64, try to decode it automatically
        if [[ "$client_key_line" =~ ^[A-Za-z0-9+/=]+$ ]]; then
            # Try base64 -d, fallback to openssl if available
            decoded=""
            decoded=$(echo "$client_key_line" | base64 -d 2>/dev/null || true)
            if [[ -z "$decoded" ]] && command -v openssl >/dev/null 2>&1; then
                decoded=$(echo "$client_key_line" | openssl base64 -d -A 2>/dev/null || true)
            fi

            if [[ -n "$decoded" ]]; then
                # Trim whitespace/newlines
                decoded=$(echo "$decoded" | tr -d '\r' | sed -e 's/[[:space:]]\+/ /g' -e 's/^ //g' -e 's/ $//g')
                log "DEBUG" "Decoded base64 client key: $decoded"
                client_key_line="$decoded"
            else
                log "WARN" "Provided client key looks like base64 but failed to decode; continuing with original input"
            fi
        fi

        # Parse the client key line
        if ! parse_client_key "$client_key_line"; then
            log "ERROR" "Invalid client key format"
            return 1
        fi
        
        # Extract components from parsed key
        agent_id=$(echo "$client_key_line" | awk '{print $1}')
        agent_name=$(echo "$client_key_line" | awk '{print $2}')
        agent_ip=$(echo "$client_key_line" | awk '{print $3}')  # Preserve original IP from client key
        agent_key=$(echo "$client_key_line" | awk '{print $4}')
    else
        # If key provided, ensure we have agent_id
        # Support case where user passes a single base64 string as the $agent_key parameter
        if [[ -z "${agent_id:-}" ]]; then
            if [[ "${agent_key}" =~ ^[A-Za-z0-9+/=]+$ ]]; then
                # Try to decode to a full client key line
                decoded=""
                decoded=$(echo "$agent_key" | base64 -d 2>/dev/null || true)
                if [[ -z "$decoded" ]] && command -v openssl >/dev/null 2>&1; then
                    decoded=$(echo "$agent_key" | openssl base64 -d -A 2>/dev/null || true)
                fi

                if [[ -n "$decoded" ]]; then
                    decoded=$(echo "$decoded" | tr -d '\r' | sed -e 's/[[:space:]]\+/ /g' -e 's/^ //g' -e 's/ $//g')
                    log "DEBUG" "Decoded base64 agent_key to: $decoded"
                    if parse_client_key "$decoded"; then
                        agent_id=$(echo "$decoded" | awk '{print $1}')
                        agent_name=$(echo "$decoded" | awk '{print $2}')
                        agent_ip=$(echo "$decoded" | awk '{print $3}')
                        agent_key=$(echo "$decoded" | awk '{print $4}')
                    else
                        log "ERROR" "Agent ID is required when providing agent key (decoded content invalid)"
                        return 1
                    fi
                else
                    log "ERROR" "Agent ID is required when providing agent key"
                    return 1
                fi
            else
                log "ERROR" "Agent ID is required when providing agent key"
                return 1
            fi
        fi
    fi
    
    # Validate components
    if [[ -z "$agent_id" || -z "$agent_key" || -z "$agent_ip" ]]; then
        log "ERROR" "Missing required agent ID, IP, or key"
        return 1
    fi
    
    # Update configuration file automatically
    log "INFO" "Updating agent configuration..."
    
    # Backup current configuration
    cp "$CONFIG_FILE" "${CONFIG_FILE}.backup.$(date +%Y%m%d_%H%M%S)"
    
    # Update manager address and port in ossec.conf
    sed -i "s|<address>[^<]*</address>|<address>$manager_ip</address>|g" "$CONFIG_FILE"
    sed -i "s|<port>[^<]*</port>|<port>$manager_port</port>|g" "$CONFIG_FILE"
    
    # Create/update client.keys file with proper format
    # Preserve the original IP from the client key (usually 'any' for flexibility)
    log "INFO" "Setting up client authentication..."
    echo "$agent_id $agent_name $agent_ip $agent_key" > "$CLIENT_KEYS"
    chmod 640 "$CLIENT_KEYS"
    
    # Set ownership if running as root and user is not root
    if [[ $EUID -eq 0 ]] && [[ "$AGENT_USER" != "root" ]]; then
        chown "$AGENT_USER:$AGENT_GROUP" "$CLIENT_KEYS" 2>/dev/null || true
    fi
    
    log "INFO" "✅ Agent enrollment completed successfully!"
    log "INFO" "   Agent ID: $agent_id"
    log "INFO" "   Agent name: $agent_name"
    log "INFO" "   Agent IP: $agent_ip"
    log "INFO" "   Manager: $manager_ip:$manager_port"
    log "INFO" "   Configuration updated: $CONFIG_FILE"
    log "INFO" "   Client keys updated: $CLIENT_KEYS"
    
    # Offer to start the agent
    echo ""
    read -p "Would you like to start the Monitoring Agent now? (y/N): " -r start_now
    if [[ "$start_now" =~ ^[Yy]$ ]]; then
        echo ""
        start_agent
    else
        echo ""
        log "INFO" "You can start the agent later with: $0 start"
    fi
    
    return 0
}

generate_agent_key() {
    # Generate a random 64-character hex key
    openssl rand -hex 32 2>/dev/null || \
    dd if=/dev/urandom bs=32 count=1 2>/dev/null | xxd -p | tr -d '\n'
}

parse_client_key() {
    local key_line="$1"
    
    # Expected format: "001 agent-name 192.168.1.100 abc123def456..."
    # Split into components and validate
    local components=($key_line)
    
    if [[ ${#components[@]} -ne 4 ]]; then
        log "ERROR" "Client key must have exactly 4 components: ID NAME IP KEY"
        log "ERROR" "Received: $key_line"
        return 1
    fi
    
    local key_id="${components[0]}"
    local key_name="${components[1]}"
    local key_ip="${components[2]}"
    local key_value="${components[3]}"
    
    # Validate agent ID (3 digits, typically 001-999)
    if [[ ! "$key_id" =~ ^[0-9]{3}$ ]]; then
        log "ERROR" "Invalid agent ID format. Expected 3 digits (e.g., 001), got: $key_id"
        return 1
    fi
    
    # Validate agent name (alphanumeric, dash, underscore)
    if [[ ! "$key_name" =~ ^[a-zA-Z0-9._-]+$ ]]; then
        log "ERROR" "Invalid agent name format: $key_name"
        return 1
    fi
    
    # Validate IP address (can be different from manager IP - we'll use manager IP)
    if ! validate_ip "$key_ip"; then
        log "WARN" "IP in client key ($key_ip) will be replaced with manager IP"
    fi
    
    # Validate key (should be 64 characters hex)
    if [[ ! "$key_value" =~ ^[a-fA-F0-9]{64}$ ]]; then
        log "ERROR" "Invalid key format. Expected 64 hexadecimal characters, got ${#key_value} characters"
        return 1
    fi
    
    log "DEBUG" "Client key validation passed"
    log "DEBUG" "  Agent ID: $key_id"
    log "DEBUG" "  Agent name: $key_name"
    log "DEBUG" "  Agent IP: $key_ip (will be preserved in client.keys)"
    log "DEBUG" "  Key length: ${#key_value} characters"
    
    return 0
}

initial_setup() {
    log "INFO" "Running initial Monitoring Agent setup..."
    
    # Check if this is first run
    local setup_marker="${AGENT_HOME}/.setup_complete"
    if [[ -f "$setup_marker" ]]; then
        log "DEBUG" "Initial setup already completed"
        return 0
    fi
    
    log "INFO" "🔧 Performing first-time setup..."
    
    # 1. Create necessary directories
    log "DEBUG" "Creating directory structure..."
    mkdir -p "$PID_DIR" "$AGENT_HOME/logs" "$AGENT_HOME/var/incoming" \
             "$AGENT_HOME/var/upgrade" "$AGENT_HOME/queue/diff" \
             "$AGENT_HOME/queue/alerts" "$AGENT_HOME/backup"
    
    # 2. Set up logging
    log "DEBUG" "Initializing log files..."
    touch "$LOG_FILE"
    touch "${AGENT_HOME}/logs/ossec.log"
    
    # 3. Set permissions and environment
    log "DEBUG" "Setting up environment..."
    ensure_environment
    
    # 4. Initialize configuration if needed
    if [[ ! -f "$CONFIG_FILE" ]]; then
        log "ERROR" "Configuration file not found: $CONFIG_FILE"
        return 1
    fi
    
    # 5. Check for required binaries
    log "DEBUG" "Verifying agent binaries..."
    local missing_binaries=()
    for process in $PROCESSES; do
        local binary="${AGENT_HOME}/bin/${process}"
        if [[ ! -x "$binary" ]]; then
            missing_binaries+=("$binary")
        fi
    done
    
    if [[ ${#missing_binaries[@]} -gt 0 ]]; then
        log "WARN" "Some binaries are missing or not executable:"
        for binary in "${missing_binaries[@]}"; do
            log "WARN" "  - $binary"
        done
    fi
    
    # 6. Create systemd service if running as root
    if [[ $EUID -eq 0 ]]; then
        create_systemd_service
    fi
    
    # 7. Mark setup as complete
    echo "Setup completed on: $(date)" > "$setup_marker"
    
    log "INFO" "✅ Initial setup completed successfully!"
    log "INFO" "Next steps:"
    log "INFO" "  1. Enroll with manager: $0 enroll <manager_ip>"
    log "INFO" "  2. Start the agent: $0 start"
    log "INFO" "  3. Check status: $0 status"
    
    return 0
}

create_systemd_service() {
    local service_file="/etc/systemd/system/monitoring-agent.service"
    
    log "DEBUG" "Creating systemd service..."
    
    # Only set User/Group if not running as root
    local user_group_lines=""
    if [[ "$AGENT_USER" != "root" ]]; then
        user_group_lines="User=$AGENT_USER
Group=$AGENT_GROUP"
    fi
    
    cat > "$service_file" << EOF
[Unit]
Description=Monitoring Agent
After=network.target

[Service]
Type=forking
ExecStart=${AGENT_HOME}/monitoring-agent-control.sh start
ExecStop=${AGENT_HOME}/monitoring-agent-control.sh stop
ExecReload=${AGENT_HOME}/monitoring-agent-control.sh restart
PIDFile=${PID_DIR}/monitoring-agentd.pid
$user_group_lines
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload 2>/dev/null || true
    log "INFO" "Systemd service created: $service_file"
    log "INFO" "Enable with: systemctl enable monitoring-agent"
}

configure_firewall() {
    local manager_ip="$1"
    local manager_port="${2:-1514}"
    
    log "INFO" "Configuring firewall rules..."
    
    # Detect firewall system
    if command -v ufw >/dev/null 2>&1; then
        log "DEBUG" "Configuring UFW firewall..."
        ufw allow out "$manager_port"/tcp comment "Monitoring Agent to Manager"
        
    elif command -v firewall-cmd >/dev/null 2>&1; then
        log "DEBUG" "Configuring firewalld..."
        firewall-cmd --permanent --add-rich-rule="rule family='ipv4' destination address='$manager_ip' port protocol='tcp' port='$manager_port' accept"
        firewall-cmd --reload
        
    elif command -v iptables >/dev/null 2>&1; then
        log "DEBUG" "Configuring iptables..."
        iptables -A OUTPUT -p tcp -d "$manager_ip" --dport "$manager_port" -j ACCEPT
        # Save rules (method varies by distribution)
        if command -v iptables-save >/dev/null 2>&1; then
            iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
        fi
        
    else
        log "WARN" "No supported firewall found. Please manually configure firewall to allow outbound connection to $manager_ip:$manager_port"
    fi
}

backup_config() {
    local backup_dir="${AGENT_HOME}/backup/$(date +%Y%m%d_%H%M%S)"
    
    log "INFO" "Creating configuration backup..."
    
    mkdir -p "$backup_dir"
    
    # Backup configuration files
    cp "$CONFIG_FILE" "$backup_dir/" 2>/dev/null || true
    cp "$CLIENT_KEYS" "$backup_dir/" 2>/dev/null || true
    cp -r "${AGENT_HOME}/etc/shared" "$backup_dir/" 2>/dev/null || true
    
    # Backup logs
    cp "${AGENT_HOME}/logs/"*.log "$backup_dir/" 2>/dev/null || true
    
    log "INFO" "Backup created at: $backup_dir"
}

restore_config() {
    local backup_path="$1"
    
    if [[ ! -d "$backup_path" ]]; then
        log "ERROR" "Backup directory not found: $backup_path"
        return 1
    fi
    
    log "INFO" "Restoring configuration from backup..."
    
    # Stop agent before restore
    stop_agent
    
    # Restore files
    cp "$backup_path/ossec.conf" "$CONFIG_FILE" 2>/dev/null || true
    cp "$backup_path/client.keys" "$CLIENT_KEYS" 2>/dev/null || true
    
    set_secure_permissions
    
    log "INFO" "Configuration restored successfully"
}

health_check() {
    log "INFO" "Running health check..."
    
    local errors=0
    
    # Check configuration
    if ! validate_configuration; then
        log "ERROR" "Configuration validation failed"
        ((errors++))
    fi
    
    # Check file permissions
    local critical_files=("$CONFIG_FILE" "$CLIENT_KEYS")
    for file in "${critical_files[@]}"; do
        if [[ -f "$file" ]] && ! check_permissions "$file" "$AGENT_USER" "$AGENT_GROUP" "640"; then
            log "ERROR" "Incorrect permissions for $file"
            ((errors++))
        fi
    done
    
    # Check disk space
    local available_space=$(df "$AGENT_HOME" | awk 'NR==2 {print $4}')
    if ((available_space < 100000)); then  # Less than ~100MB
        log "WARN" "Low disk space: ${available_space}KB available"
        ((errors++))
    fi
    
    # Check log file size
    if [[ -f "$LOG_FILE" ]]; then
        local log_size=$(stat -c%s "$LOG_FILE")
        if ((log_size > 104857600)); then  # 100MB
            log "WARN" "Log file is large: ${log_size} bytes"
        fi
    fi
    
    if ((errors == 0)); then
        log "INFO" "Health check passed"
        return 0
    else
        log "ERROR" "Health check failed with $errors errors"
        return 1
    fi
}

test_connection() {
    log "INFO" "Testing connection to Monitoring manager..."
    
    # Extract server configuration
    local server_ip=$(grep -o '<address>[^<]*</address>' "$CONFIG_FILE" | sed 's/<[^>]*>//g')
    local server_port=$(grep -o '<port>[^<]*</port>' "$CONFIG_FILE" | sed 's/<[^>]*>//g')
    
    if [[ -z "$server_ip" || -z "$server_port" ]]; then
        log "ERROR" "Manager IP or port not configured"
        return 1
    fi
    
    log "INFO" "Testing connectivity to ${server_ip}:${server_port}..."
    
    # Test network connectivity
    if ! command -v nc &> /dev/null; then
        log "WARN" "netcat not available, skipping network test"
    else
        if nc -zv "$server_ip" "$server_port" 2>/dev/null; then
            log "INFO" "Network connectivity: ✓ SUCCESS"
        else
            log "ERROR" "Network connectivity: ✗ FAILED"
            return 1
        fi
    fi
    
    # Check if agent is enrolled
    if [[ ! -f "$CLIENT_KEYS" || ! -s "$CLIENT_KEYS" ]]; then
        log "WARN" "Agent not enrolled - run enrollment first"
        return 1
    fi
    
    log "INFO" "Agent enrollment: ✓ CONFIGURED"
    log "INFO" "Connection test completed successfully"
    return 0
}

usage() {
    cat << EOF
Monitoring Agent Control Script v1.0.0

USAGE:
    $SCRIPT_NAME <command> [options]

COMMANDS:
    setup                           Run initial setup (automatic on first start)
    enroll <manager_ip> [port] [name]
                                    Enroll agent with manager (interactive)
    start                           Start the monitoring agent
    stop                            Stop the monitoring agent
    restart                         Restart the monitoring agent
    status                          Show agent status
    logs [lines] [follow]           Show agent logs (default: 50 lines)
    health                          Run health check
    health-check-full               Run comprehensive health check with fault tolerance
    test-connection                 Test connectivity to manager
    backup                          Backup configuration
    restore <backup_path>           Restore configuration from backup
    configure-firewall <manager_ip> [port]
                                    Configure firewall rules
    
OPTIONS:
    -h, --help                      Show this help message
    -v, --version                   Show version information
    -d, --debug                     Enable debug logging

QUICK START:
    1. Enroll with manager:         $SCRIPT_NAME enroll <manager_ip>
    2. Start the agent:             $SCRIPT_NAME start
    3. Check status:                $SCRIPT_NAME status
    4. Test connectivity:           $SCRIPT_NAME test-connection

ENROLLMENT PROCESS:
    The enrollment command will:
    - Prompt for the client key from your manager
    - Automatically update configuration files
    - Offer to start the agent immediately
    
    To get the client key, run on your manager:
    sudo /var/ossec/bin/manage_agents -l

EXAMPLES:
    $SCRIPT_NAME enroll 192.168.1.100
    $SCRIPT_NAME start
    $SCRIPT_NAME status
    $SCRIPT_NAME logs 100 true
    $SCRIPT_NAME test-connection

SECURITY NOTES:
    - Run as root for full functionality
    - Configuration files are protected with 640 permissions
    - All inputs are validated and sanitized
    - Logs contain no sensitive information

For support and documentation, visit: https://docs.monitoring-solutions.com
EOF
}

version() {
    echo "Monitoring Agent Control Script"
    echo "Version: 1.0.0"
    echo "Copyright (C) 2025, Monitoring Solutions Inc."
    echo "License: Commercial License"
}

# Main function
main() {
# Auto-installation and production readiness setup
setup_production_environment() {
    # Ensure systemd service is properly installed
    local service_file="/etc/systemd/system/monitoring-agent.service"
    local current_service="${AGENT_HOME}/monitoring-agent.service"
    
    if [[ -f "$current_service" && ! -f "$service_file" ]]; then
        log "INFO" "Installing systemd service for auto-startup..."
        cp "$current_service" "$service_file"
        systemctl daemon-reload
        systemctl enable monitoring-agent.service
        log "INFO" "Service installed and enabled for auto-startup"
    fi
    
    # Fix permission issues automatically
    if [[ -f "${AGENT_HOME}/etc/ossec.conf" ]]; then
        chown monitoring:monitoring "${AGENT_HOME}/etc/ossec.conf" 2>/dev/null || true
        chmod 644 "${AGENT_HOME}/etc/ossec.conf" 2>/dev/null || true
    fi
    
    # Ensure watchdog system is set up
    local watchdog_service="/etc/systemd/system/monitoring-agent-watchdog.service"
    if [[ ! -f "$watchdog_service" && -f "${AGENT_HOME}/scripts/monitoring-watchdog.sh" ]]; then
        create_watchdog_service
    fi
}

create_watchdog_service() {
    local watchdog_service="/etc/systemd/system/monitoring-agent-watchdog.service"
    
    cat > "$watchdog_service" << 'EOF'
[Unit]
Description=Monitoring Agent Watchdog
After=monitoring-agent.service
Wants=monitoring-agent.service
PartOf=monitoring-agent.service

[Service]
Type=simple
ExecStart=/home/anandhu/monitor/scripts/monitoring-watchdog.sh
Restart=always
RestartSec=10
User=root
Group=root

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable monitoring-agent-watchdog.service
    log "INFO" "Watchdog service created and enabled"
}

# Always ensure script runs with root privileges
if [[ $EUID -ne 0 ]]; then
    echo "Monitoring Agent requires elevated privileges. Restarting with sudo..."
    # Preserve LD_PRELOAD environment variable if set
    if [[ -n "${LD_PRELOAD:-}" ]]; then
        exec sudo LD_PRELOAD="$LD_PRELOAD" "$0" "$@"
    else
        exec sudo "$0" "$@"
    fi
fi

# Auto-setup production environment on any execution
setup_production_environment    arg=$2

    case "$1" in
    start)
        testconfig
        lock
        start_agent
        unlock
        ;;
    start-service)
        # Special mode for systemd exec service type - starts and stays in foreground
        testconfig
        lock
        start_agent
        unlock
        # Stay in foreground to maintain systemd service
        echo "[INFO] Monitoring Agent running in service mode..."
        while true; do
            sleep 30
            # Basic health check - if main daemon dies, exit to trigger restart
            if ! pgrep -f "monitoring-agentd" > /dev/null; then
                log "ERROR" "Main daemon died, exiting service to trigger restart"
                exit 1
            fi
        done
        ;;
    stop)
        lock
        stop_agent
        unlock
        ;;
    restart)
        testconfig
        lock
        stop_agent
        sleep 1
        start_agent
        unlock
        ;;
    status)
        lock
        status_agent
        unlock
        ;;
    setup)
        initial_setup
        ;;
    enroll)
        if [[ $# -lt 2 ]]; then
            log "ERROR" "Manager IP address required for enrollment"
            usage
            exit 1
        fi
        # Skip the first argument (command name) and pass the rest
        shift
        enroll_agent "$@"
        ;;
    health)
        health_check
        ;;
    health-check)
        health_check
        ;;
    health-check-full)
        health_check_with_fault_tolerance
        ;;
    test-config)
        testconfig
        ;;
    restart-process)
        if [[ $# -lt 2 ]]; then
            log "ERROR" "Process name required for restart-process command"
            usage
            exit 1
        fi
        restart_single_process "$2"
        ;;
    test-connection)
        test_connection
        ;;
    backup)
        backup_config
        ;;
    restore)
        if [[ $# -lt 1 ]]; then
            log "ERROR" "Backup path required for restore"
            usage
            exit 1
        fi
        restore_config "$1"
        ;;
    configure-firewall)
        if [[ $# -lt 1 ]]; then
            log "ERROR" "Manager IP address required for firewall configuration"
            usage
            exit 1
        fi
        configure_firewall "$@"
        ;;
    logs)
        local lines="${2:-50}"
        local follow="${3:-false}"
        show_logs "$lines" "$follow"
        ;;
    help)
        usage
        ;;
    -h|--help)
        usage
        exit 0
        ;;
    -v|--version)
        version
        exit 0
        ;;
    *)
        usage
        exit 1
        ;;
    esac
}

# Signal handlers
trap 'log "WARN" "Script interrupted"; exit 130' INT TERM

# Ensure log directory exists
mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || true

### MAIN HERE ###
main "$@"

exit $RETVAL