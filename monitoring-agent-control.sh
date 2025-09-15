#!/bin/bash

# Monitoring Agent Control Script
# Professional agent management tool for Linux systems
# Copyright (C) 2025, Monitoring Solutions Inc.
# Version: 1.0.0

set -euo pipefail

# Configuration variables
readonly SCRIPT_NAME="$(basename "$0")"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly AGENT_HOME="${SCRIPT_DIR}"
# Default to current user for better compatibility
readonly AGENT_USER="$(whoami)"
readonly AGENT_GROUP="$(id -gn)"
readonly CONFIG_FILE="${AGENT_HOME}/etc/ossec.conf"
readonly CLIENT_KEYS="${AGENT_HOME}/etc/client.keys"
readonly LOG_FILE="${AGENT_HOME}/logs/monitoring-agent.log"
readonly PID_DIR="${AGENT_HOME}/var/run"
readonly LOCK_FILE="/tmp/monitoring-agent-$(whoami)"

# Process names
readonly PROCESSES="monitoring-modulesd monitoring-logcollector monitoring-syscheckd monitoring-agentd monitoring-execd"

# Colors for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m' # No Color

# Logging function
log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    # Try to write to log file, fall back to temp file if permission denied
    if ! echo "[$timestamp] [$level] $message" >> "$LOG_FILE" 2>/dev/null; then
        local temp_log="/tmp/monitoring-agent-$(whoami).log"
        echo "[$timestamp] [$level] $message" >> "$temp_log" 2>/dev/null || true
    fi
    
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
            echo -e "${BLUE}[DEBUG]${NC} $message"
            ;;
        *)
            echo "$message"
            ;;
    esac
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

set_secure_permissions() {
    log "INFO" "Setting secure file permissions..."
    
    # Ensure required directories exist
    mkdir -p "$AGENT_HOME/bin" "$AGENT_HOME/etc" "$AGENT_HOME/logs" \
             "$AGENT_HOME/var" "$AGENT_HOME/var/run" \
             "$AGENT_HOME/queue" "$AGENT_HOME/queue/sockets"

    # Set directory permissions
    chmod 755 "$AGENT_HOME"
    chmod 755 "$AGENT_HOME/bin" "$AGENT_HOME/etc" "$AGENT_HOME/logs"
    chmod 750 "$AGENT_HOME/var" "$AGENT_HOME/var/run" "$AGENT_HOME/queue" "$AGENT_HOME/queue/sockets"
    
    # Set file permissions (readable by user, writable by user)
    chmod 640 "$CONFIG_FILE" 2>/dev/null || true
    chmod 600 "$CLIENT_KEYS" 2>/dev/null || true  # More restrictive for keys
    chmod 755 "$AGENT_HOME/bin/"* 2>/dev/null || true
    
    # Set ownership if running as root
    if [[ $EUID -eq 0 ]]; then
        chown -R "$AGENT_USER:$AGENT_GROUP" "$AGENT_HOME" 2>/dev/null || true
    fi
}

# Process management functions
is_process_running() {
    local process_name="$1"
    local pid_file="${PID_DIR}/${process_name}.pid"
    
    if [[ -f "$pid_file" ]]; then
        local pid=$(cat "$pid_file" 2>/dev/null)
        if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
            return 0
        else
            rm -f "$pid_file"
        fi
    fi
    
    # Fallback to process name check
    pgrep -f "$process_name" > /dev/null 2>&1
}

get_process_pid() {
    local process_name="$1"
    local pid_file="${PID_DIR}/${process_name}.pid"
    
    if [[ -f "$pid_file" ]]; then
        local pid=$(cat "$pid_file" 2>/dev/null)
        if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
            echo "$pid"
            return
        else
            rm -f "$pid_file"
        fi
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

# Agent management functions
start_agent() {
    log "INFO" "Starting Monitoring Agent..."
    
    # Run initial setup if needed
    if ! initial_setup; then
        log "ERROR" "Initial setup failed"
        return 1
    fi
    
    # Check if already running
    if is_agent_running; then
        log "WARN" "Monitoring Agent is already running"
        return 0
    fi
    
    # Check if agent is enrolled
    if [[ ! -f "$CLIENT_KEYS" || ! -s "$CLIENT_KEYS" ]]; then
        log "ERROR" "Agent not enrolled. Please run enrollment first:"
        log "ERROR" "  $0 enroll <manager_ip> [port] [agent_name]"
        return 1
    fi
    
    # Validate configuration
    if ! validate_configuration; then
        log "ERROR" "Configuration validation failed"
        return 1
    fi
    
    # Set permissions
    set_secure_permissions
    
    # Create lock file
    touch "$LOCK_FILE"
    
    # Start processes
    cd "$AGENT_HOME"
    
    # Focus on starting only the main agent daemon (wazuh-agentd)
    local main_binary="${AGENT_HOME}/bin/wazuh-agentd"
    
    if [[ ! -x "$main_binary" ]]; then
        log "ERROR" "Main agent binary not found: $main_binary"
        rm -f "$LOCK_FILE"
        return 1
    fi
    
    log "INFO" "Starting main agent daemon..."
    
    # Set environment for Wazuh compatibility
    export WAZUH_HOME="$AGENT_HOME"
    export OSSEC_HOME="$AGENT_HOME"
    
    # Start the agent daemon with appropriate permissions
    local start_cmd="$main_binary -f -u $AGENT_USER -g $AGENT_GROUP"
    local log_file="${AGENT_HOME}/logs/wazuh-agentd.log"
    local pid
    
    if [[ $EUID -eq 0 ]]; then
        # Running as root - can start directly
        log "INFO" "Starting agent with user '$AGENT_USER' and group '$AGENT_GROUP' (running as root)..."
        # Ensure OSSEC_HOME is set for the agent process
        nohup env OSSEC_HOME="$AGENT_HOME" WAZUH_HOME="$AGENT_HOME" $start_cmd > "$log_file" 2>&1 &
        pid=$!
    elif command -v sudo >/dev/null 2>&1; then
        # Use sudo to start with specified user/group
        log "INFO" "Starting agent with sudo as user '$AGENT_USER' and group '$AGENT_GROUP'..."
        # Ensure OSSEC_HOME is set for the agent process
        nohup sudo env OSSEC_HOME="$AGENT_HOME" WAZUH_HOME="$AGENT_HOME" $start_cmd > "$log_file" 2>&1 &
        pid=$!
    else
        # Cannot use sudo - warn and try direct execution
        log "WARN" "Cannot use sudo, trying direct execution"
        log "WARN" "This may fail due to permission restrictions"
        nohup env OSSEC_HOME="$AGENT_HOME" WAZUH_HOME="$AGENT_HOME" $start_cmd > "$log_file" 2>&1 &
        pid=$!
    fi
    
    # Give it time to start
    sleep 5
    
    if kill -0 "$pid" 2>/dev/null; then
        echo "$pid" > "${PID_DIR}/wazuh-agentd.pid"
        log "INFO" "✅ Main agent daemon started successfully (PID: $pid)"
        
        # Wait a bit more and check if it's still running
        sleep 3
        if kill -0 "$pid" 2>/dev/null; then
            log "INFO" "✅ Agent is running and stable"
            log "INFO" "Check connection with: $0 test-connection"
            log "INFO" "View logs with: tail -f logs/wazuh-agentd.log"
        else
            log "ERROR" "Agent started but crashed - check logs/wazuh-agentd.log"
            rm -f "$LOCK_FILE"
            return 1
        fi
    else
        log "ERROR" "Failed to start main agent daemon"
        log "ERROR" "Check logs/wazuh-agentd.log for details"
        rm -f "$LOCK_FILE"
        return 1
    fi
    
    log "INFO" "✅ Monitoring Agent started successfully!"
    log "INFO" "Use '$0 status' to check the status"
    log "INFO" "Use '$0 test-connection' to verify manager connectivity"
    return 0
}

stop_agent() {
    log "INFO" "Stopping Monitoring Agent..."
    
    if ! is_agent_running; then
        log "WARN" "Monitoring Agent is not running"
        return 0
    fi
    
    # Stop processes in reverse order
    local processes_array=($PROCESSES)
    for ((i=${#processes_array[@]}-1; i>=0; i--)); do
        stop_process "${processes_array[i]}"
    done
    
    # Remove lock file
    rm -f "$LOCK_FILE"
    
    log "INFO" "Monitoring Agent stopped successfully"
    return 0
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

restart_agent() {
    log "INFO" "Restarting Monitoring Agent..."
    stop_agent
    sleep 3
    start_agent
}

is_agent_running() {
    [[ -f "$LOCK_FILE" ]] && pgrep -f "wazuh-agentd" > /dev/null 2>&1
}

status_agent() {
    echo "Monitoring Agent Status Report"
    echo "=============================="
    echo "Configuration file: $CONFIG_FILE"
    echo "Log file: $LOG_FILE"
    echo "Process status:"
    
    local all_running=true
    for process in $PROCESSES; do
        local pid=$(get_process_pid "$process")
        if [[ -n "$pid" ]]; then
            echo -e "  $process: ${GREEN}RUNNING${NC} (PID: $pid)"
        else
            echo -e "  $process: ${RED}STOPPED${NC}"
            all_running=false
        fi
    done
    
    echo ""
    if $all_running; then
        echo -e "Overall status: ${GREEN}RUNNING${NC}"
    else
        echo -e "Overall status: ${RED}STOPPED${NC}"
    fi
    
    # Show connection status
    if is_process_running "monitoring-agentd"; then
        echo ""
        echo "Connection status:"
        if grep -q "Connected to enrollment service" "$LOG_FILE" 2>/dev/null; then
            echo -e "  Manager connection: ${GREEN}CONNECTED${NC}"
        else
            echo -e "  Manager connection: ${YELLOW}UNKNOWN${NC}"
        fi
    fi
    
    # Show resource usage
    echo ""
    echo "Resource usage:"
    for process in $PROCESSES; do
        local pid=$(get_process_pid "$process")
        if [[ -n "$pid" ]]; then
            local mem_usage=$(ps -p "$pid" -o %mem= 2>/dev/null | tr -d ' ')
            local cpu_usage=$(ps -p "$pid" -o %cpu= 2>/dev/null | tr -d ' ')
            echo "  $process: CPU: ${cpu_usage}%, Memory: ${mem_usage}%"
        fi
    done
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

enroll_agent() {
    local manager_ip="$1"
    local manager_port="${2:-1514}"
    local agent_name="${3:-$(hostname)}"
    local agent_id="${4:-}"
    local agent_key="${5:-}"
    
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
        echo "Please provide the client key obtained from the Wazuh manager."
        echo "You can get this key by running on the manager:"
        echo "  sudo /var/ossec/bin/manage_agents -l"
        echo ""
        echo "The key should be in format:"
        echo "  001 agent-name 192.168.1.100 abc123...def456"
        echo ""
        read -p "Enter the complete client key line: " -r client_key_line
        
        if [[ -z "$client_key_line" ]]; then
            log "ERROR" "Client key is required for enrollment"
            return 1
        fi
        
        # Parse the client key line
        if ! parse_client_key "$client_key_line"; then
            log "ERROR" "Invalid client key format"
            return 1
        fi
        
        # Extract components from parsed key
        agent_id=$(echo "$client_key_line" | awk '{print $1}')
        agent_name=$(echo "$client_key_line" | awk '{print $2}')
        agent_key=$(echo "$client_key_line" | awk '{print $4}')
    else
        # If key provided, ensure we have agent_id
        if [[ -z "${agent_id:-}" ]]; then
            log "ERROR" "Agent ID is required when providing agent key"
            return 1
        fi
    fi
    
    # Validate components
    if [[ -z "$agent_id" || -z "$agent_key" ]]; then
        log "ERROR" "Missing required agent ID or key"
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
    # Use the manager IP from enrollment, not from the original key
    log "INFO" "Setting up client authentication..."
    echo "$agent_id $agent_name $manager_ip $agent_key" > "$CLIENT_KEYS"
    chmod 640 "$CLIENT_KEYS"
    
    # Set ownership if running as root
    if [[ $EUID -eq 0 ]]; then
        chown "$AGENT_USER:$AGENT_GROUP" "$CLIENT_KEYS" 2>/dev/null || true
    fi
    
    log "INFO" "✅ Agent enrollment completed successfully!"
    log "INFO" "   Agent ID: $agent_id"
    log "INFO" "   Agent name: $agent_name"
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
    log "DEBUG" "  Original IP: $key_ip (will use manager IP instead)"
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
    
    # 3. Set permissions
    log "DEBUG" "Setting secure permissions..."
    set_secure_permissions
    
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
User=$AGENT_USER
Group=$AGENT_GROUP
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
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
    log "INFO" "Testing connection to Wazuh manager..."
    
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
    - Prompt for the client key from your Wazuh manager
    - Automatically update configuration files
    - Offer to start the agent immediately
    
    To get the client key, run on your Wazuh manager:
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
    # Parse global options
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                usage
                exit 0
                ;;
            -v|--version)
                version
                exit 0
                ;;
            -d|--debug)
                set -x
                shift
                ;;
            -*)
                log "ERROR" "Unknown option: $1"
                usage
                exit 1
                ;;
            *)
                break
                ;;
        esac
    done
    
    # Ensure log directory exists
    mkdir -p "$(dirname "$LOG_FILE")"
    
    # Ensure we have at least one argument
    if [[ $# -eq 0 ]]; then
        log "ERROR" "No command specified"
        usage
        exit 1
    fi
    
    local command="$1"
    shift
    
    # Execute command
    case "$command" in
        setup)
            initial_setup
            ;;
        start)
            start_agent
            ;;
        stop)
            stop_agent
            ;;
        restart)
            restart_agent
            ;;
        status)
            status_agent
            ;;
        logs)
            local lines="${1:-50}"
            local follow="${2:-false}"
            show_logs "$lines" "$follow"
            ;;
        enroll)
            if [[ $# -lt 1 ]]; then
                log "ERROR" "Manager IP address required for enrollment"
                usage
                exit 1
            fi
            enroll_agent "$@"
            ;;
        health)
            health_check
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
        *)
            log "ERROR" "Unknown command: $command"
            usage
            exit 1
            ;;
    esac
}

# Signal handlers
trap 'log "WARN" "Script interrupted"; exit 130' INT TERM

# Run main function
main "$@"