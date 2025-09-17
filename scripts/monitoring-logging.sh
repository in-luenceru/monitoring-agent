#!/bin/bash
# Monitoring Agent Enhanced Logging and Alerting System
# Comprehensive logging, monitoring, and notification system
# Copyright (C) 2025, Monitoring Solutions Inc.

set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly AGENT_HOME="$(dirname "$SCRIPT_DIR")"
readonly CONFIG_FILE="${AGENT_HOME}/etc/monitoring-alerts.conf"
readonly LOG_DIR="${AGENT_HOME}/logs"
readonly MAIN_LOG="${LOG_DIR}/monitoring-agent.log"
readonly ALERT_LOG="${LOG_DIR}/monitoring-alerts.log"
readonly METRICS_LOG="${LOG_DIR}/monitoring-metrics.log"
readonly STATE_DIR="${AGENT_HOME}/var/run"

# Default configuration
readonly DEFAULT_CONFIG="
# Monitoring Agent Alert Configuration

# Email settings
SMTP_SERVER=\"\"
SMTP_PORT=\"587\"
SMTP_USER=\"\"
SMTP_PASSWORD=\"\"
SMTP_FROM=\"monitoring-agent@localhost\"
SMTP_TO=\"admin@localhost\"
SMTP_TLS=\"true\"

# Webhook settings
WEBHOOK_URL=\"\"
WEBHOOK_METHOD=\"POST\"
WEBHOOK_HEADERS=\"Content-Type: application/json\"

# Slack settings
SLACK_WEBHOOK_URL=\"\"
SLACK_CHANNEL=\"#monitoring\"
SLACK_USERNAME=\"MonitoringAgent\"

# Discord settings
DISCORD_WEBHOOK_URL=\"\"

# Microsoft Teams settings
TEAMS_WEBHOOK_URL=\"\"

# Alert thresholds
DISK_USAGE_WARNING=\"85\"
DISK_USAGE_CRITICAL=\"95\"
MEMORY_USAGE_WARNING=\"80\"
MEMORY_USAGE_CRITICAL=\"90\"
CPU_USAGE_WARNING=\"80\"
CPU_USAGE_CRITICAL=\"95\"
LOAD_AVERAGE_WARNING=\"5.0\"
LOAD_AVERAGE_CRITICAL=\"10.0\"

# Process monitoring
PROCESS_DOWN_WARNING=\"30\"     # seconds
PROCESS_DOWN_CRITICAL=\"300\"   # seconds
MAX_RESTART_ATTEMPTS=\"5\"
RESTART_WINDOW=\"3600\"         # seconds (1 hour)

# Log file monitoring
MAX_LOG_SIZE=\"104857600\"      # 100MB
LOG_ROTATION_ENABLED=\"true\"
MAX_LOG_FILES=\"10\"

# Notification settings
ALERT_COOLDOWN=\"1800\"         # 30 minutes
HEARTBEAT_INTERVAL=\"3600\"     # 1 hour
ENABLE_EMAIL=\"false\"
ENABLE_WEBHOOK=\"false\"
ENABLE_SLACK=\"false\"
ENABLE_DISCORD=\"false\"
ENABLE_TEAMS=\"false\"
ENABLE_SYSLOG=\"true\"
"

# Alert levels
declare -A ALERT_LEVELS=(
    ["DEBUG"]=0
    ["INFO"]=1
    ["WARN"]=2
    ["ERROR"]=3
    ["CRITICAL"]=4
)

# State tracking
declare -A ALERT_LAST_SENT
declare -A PROCESS_RESTART_COUNT
declare -A PROCESS_RESTART_TIMES

# Initialize configuration
init_config() {
    if [[ ! -f "$CONFIG_FILE" ]]; then
        echo "Creating default alert configuration..."
        echo "$DEFAULT_CONFIG" > "$CONFIG_FILE"
        chmod 600 "$CONFIG_FILE"
    fi
    
    # Source configuration
    source "$CONFIG_FILE"
}

# Enhanced logging function
log_event() {
    local level="$1"
    local component="$2"
    local message="$3"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local hostname=$(hostname)
    local pid=$$
    
    # Create structured log entry
    local log_entry="[$timestamp] [$hostname] [$pid] [$level] [$component] $message"
    
    # Write to main log
    echo "$log_entry" >> "$MAIN_LOG"
    
    # Write to alert log if warning or above
    if [[ ${ALERT_LEVELS[$level]} -ge ${ALERT_LEVELS["WARN"]} ]]; then
        echo "$log_entry" >> "$ALERT_LOG"
        
        # Check if alert should be sent
        check_and_send_alert "$level" "$component" "$message"
    fi
    
    # Write to syslog if enabled
    if [[ "${ENABLE_SYSLOG:-true}" == "true" ]]; then
        logger -t "monitoring-agent" -p "daemon.$level" "[$component] $message"
    fi
    
    # Write to console if interactive
    if [[ -t 1 ]]; then
        case "$level" in
            "ERROR"|"CRITICAL")
                echo -e "\033[0;31m$log_entry\033[0m" >&2
                ;;
            "WARN")
                echo -e "\033[1;33m$log_entry\033[0m" >&2
                ;;
            "INFO")
                echo -e "\033[0;32m$log_entry\033[0m"
                ;;
            *)
                echo "$log_entry"
                ;;
        esac
    fi
}

# Metrics logging
log_metrics() {
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local hostname=$(hostname)
    
    # System metrics
    local cpu_usage=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | sed 's/%us,//')
    local memory_info=$(free -m | awk 'NR==2{printf "used:%d,total:%d,percent:%.1f", $3,$2,$3*100/$2}')
    local disk_usage=$(df "${AGENT_HOME}" | awk 'NR==2{printf "used:%d,total:%d,percent:%s", $3,$2,$5}' | sed 's/%//')
    local load_avg=$(uptime | awk -F'load average:' '{print $2}' | awk '{print $1}' | sed 's/,//')
    
    # Process metrics
    local running_processes=0
    local total_processes=${#DAEMONS[@]}
    
    for daemon in monitoring-agentd monitoring-execd monitoring-modulesd monitoring-logcollector monitoring-syscheckd; do
        if pgrep -f "$daemon" > /dev/null; then
            running_processes=$((running_processes + 1))
        fi
    done
    
    # Log file sizes
    local main_log_size=$(stat -f%z "$MAIN_LOG" 2>/dev/null || stat -c%s "$MAIN_LOG" 2>/dev/null || echo 0)
    local alert_log_size=$(stat -f%z "$ALERT_LOG" 2>/dev/null || stat -c%s "$ALERT_LOG" 2>/dev/null || echo 0)
    
    # Create metrics entry
    local metrics_entry="$timestamp,$hostname,cpu:$cpu_usage,memory:$memory_info,disk:$disk_usage,load:$load_avg,processes:$running_processes/$total_processes,log_sizes:main=$main_log_size;alert=$alert_log_size"
    
    echo "$metrics_entry" >> "$METRICS_LOG"
    
    # Check thresholds and generate alerts
    check_system_thresholds "$cpu_usage" "$memory_info" "$disk_usage" "$load_avg" "$running_processes" "$total_processes"
}

# Check system thresholds and generate alerts
check_system_thresholds() {
    local cpu_usage="$1"
    local memory_info="$2"
    local disk_usage="$3"
    local load_avg="$4"
    local running_processes="$5"
    local total_processes="$6"
    
    # Extract numeric values
    local memory_percent=$(echo "$memory_info" | grep -o 'percent:[0-9.]*' | cut -d: -f2)
    local disk_percent=$(echo "$disk_usage" | grep -o '[0-9]*$')
    
    # CPU usage check
    if [[ $(echo "$cpu_usage > ${CPU_USAGE_CRITICAL:-95}" | bc) -eq 1 ]]; then
        log_event "CRITICAL" "SYSTEM" "CPU usage critical: ${cpu_usage}%"
    elif [[ $(echo "$cpu_usage > ${CPU_USAGE_WARNING:-80}" | bc) -eq 1 ]]; then
        log_event "WARN" "SYSTEM" "CPU usage high: ${cpu_usage}%"
    fi
    
    # Memory usage check
    if [[ $(echo "$memory_percent > ${MEMORY_USAGE_CRITICAL:-90}" | bc) -eq 1 ]]; then
        log_event "CRITICAL" "SYSTEM" "Memory usage critical: ${memory_percent}%"
    elif [[ $(echo "$memory_percent > ${MEMORY_USAGE_WARNING:-80}" | bc) -eq 1 ]]; then
        log_event "WARN" "SYSTEM" "Memory usage high: ${memory_percent}%"
    fi
    
    # Disk usage check
    if [[ $disk_percent -gt ${DISK_USAGE_CRITICAL:-95} ]]; then
        log_event "CRITICAL" "SYSTEM" "Disk usage critical: ${disk_percent}%"
    elif [[ $disk_percent -gt ${DISK_USAGE_WARNING:-85} ]]; then
        log_event "WARN" "SYSTEM" "Disk usage high: ${disk_percent}%"
    fi
    
    # Load average check
    if [[ $(echo "$load_avg > ${LOAD_AVERAGE_CRITICAL:-10.0}" | bc) -eq 1 ]]; then
        log_event "CRITICAL" "SYSTEM" "Load average critical: $load_avg"
    elif [[ $(echo "$load_avg > ${LOAD_AVERAGE_WARNING:-5.0}" | bc) -eq 1 ]]; then
        log_event "WARN" "SYSTEM" "Load average high: $load_avg"
    fi
    
    # Process count check
    if [[ $running_processes -lt $total_processes ]]; then
        local failed_count=$((total_processes - running_processes))
        if [[ $failed_count -ge 3 ]]; then
            log_event "CRITICAL" "PROCESSES" "$failed_count critical processes down"
        elif [[ $failed_count -ge 1 ]]; then
            log_event "ERROR" "PROCESSES" "$failed_count processes down"
        fi
    fi
}

# Check if alert should be sent (respects cooldown)
check_and_send_alert() {
    local level="$1"
    local component="$2"
    local message="$3"
    local alert_key="${component}_${level}"
    local current_time=$(date +%s)
    local cooldown=${ALERT_COOLDOWN:-1800}
    
    # Check if we're in cooldown period for this alert type
    local last_sent=${ALERT_LAST_SENT[$alert_key]:-0}
    if [[ $((current_time - last_sent)) -lt $cooldown ]]; then
        return 0  # Skip sending alert
    fi
    
    # Send alert through configured channels
    send_alert "$level" "$component" "$message"
    
    # Update last sent time
    ALERT_LAST_SENT[$alert_key]=$current_time
}

# Send alert through configured channels
send_alert() {
    local level="$1"
    local component="$2"
    local message="$3"
    local hostname=$(hostname)
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    # Create alert payload
    local alert_subject="[$level] Monitoring Agent Alert - $hostname"
    local alert_body="Alert Details:
Time: $timestamp
Host: $hostname
Level: $level
Component: $component
Message: $message

--
Monitoring Agent Alert System"
    
    # Send via email
    if [[ "${ENABLE_EMAIL:-false}" == "true" && -n "${SMTP_SERVER:-}" ]]; then
        send_email_alert "$alert_subject" "$alert_body"
    fi
    
    # Send via webhook
    if [[ "${ENABLE_WEBHOOK:-false}" == "true" && -n "${WEBHOOK_URL:-}" ]]; then
        send_webhook_alert "$level" "$component" "$message" "$hostname" "$timestamp"
    fi
    
    # Send via Slack
    if [[ "${ENABLE_SLACK:-false}" == "true" && -n "${SLACK_WEBHOOK_URL:-}" ]]; then
        send_slack_alert "$level" "$component" "$message" "$hostname" "$timestamp"
    fi
    
    # Send via Discord
    if [[ "${ENABLE_DISCORD:-false}" == "true" && -n "${DISCORD_WEBHOOK_URL:-}" ]]; then
        send_discord_alert "$level" "$component" "$message" "$hostname" "$timestamp"
    fi
    
    # Send via Microsoft Teams
    if [[ "${ENABLE_TEAMS:-false}" == "true" && -n "${TEAMS_WEBHOOK_URL:-}" ]]; then
        send_teams_alert "$level" "$component" "$message" "$hostname" "$timestamp"
    fi
}

# Email alert function
send_email_alert() {
    local subject="$1"
    local body="$2"
    
    if command -v mail >/dev/null 2>&1; then
        echo "$body" | mail -s "$subject" "${SMTP_TO}"
    elif command -v sendmail >/dev/null 2>&1; then
        {
            echo "To: ${SMTP_TO}"
            echo "Subject: $subject"
            echo ""
            echo "$body"
        } | sendmail "${SMTP_TO}"
    else
        log_event "WARN" "ALERT" "Email alert failed: no mail command available"
    fi
}

# Webhook alert function
send_webhook_alert() {
    local level="$1"
    local component="$2"
    local message="$3"
    local hostname="$4"
    local timestamp="$5"
    
    local json_payload=$(cat << EOF
{
    "timestamp": "$timestamp",
    "hostname": "$hostname",
    "level": "$level",
    "component": "$component",
    "message": "$message",
    "source": "monitoring-agent"
}
EOF
)
    
    curl -X "${WEBHOOK_METHOD:-POST}" \
         -H "${WEBHOOK_HEADERS:-Content-Type: application/json}" \
         -d "$json_payload" \
         "${WEBHOOK_URL}" \
         --connect-timeout 10 \
         --max-time 30 \
         --silent \
         >/dev/null 2>&1 || log_event "WARN" "ALERT" "Webhook alert failed"
}

# Slack alert function
send_slack_alert() {
    local level="$1"
    local component="$2"
    local message="$3"
    local hostname="$4"
    local timestamp="$5"
    
    local color
    case "$level" in
        "CRITICAL") color="danger" ;;
        "ERROR") color="danger" ;;
        "WARN") color="warning" ;;
        *) color="good" ;;
    esac
    
    local slack_payload=$(cat << EOF
{
    "channel": "${SLACK_CHANNEL:-#monitoring}",
    "username": "${SLACK_USERNAME:-MonitoringAgent}",
    "attachments": [
        {
            "color": "$color",
            "title": "[$level] Monitoring Agent Alert",
            "fields": [
                {
                    "title": "Host",
                    "value": "$hostname",
                    "short": true
                },
                {
                    "title": "Component",
                    "value": "$component",
                    "short": true
                },
                {
                    "title": "Message",
                    "value": "$message",
                    "short": false
                }
            ],
            "footer": "Monitoring Agent",
            "ts": $(date +%s)
        }
    ]
}
EOF
)
    
    curl -X POST \
         -H "Content-Type: application/json" \
         -d "$slack_payload" \
         "${SLACK_WEBHOOK_URL}" \
         --connect-timeout 10 \
         --max-time 30 \
         --silent \
         >/dev/null 2>&1 || log_event "WARN" "ALERT" "Slack alert failed"
}

# Discord alert function
send_discord_alert() {
    local level="$1"
    local component="$2"
    local message="$3"
    local hostname="$4"
    local timestamp="$5"
    
    local color
    case "$level" in
        "CRITICAL") color="15158332" ;;  # Red
        "ERROR") color="15158332" ;;     # Red
        "WARN") color="16776960" ;;      # Yellow
        *) color="3066993" ;;            # Green
    esac
    
    local discord_payload=$(cat << EOF
{
    "embeds": [
        {
            "title": "[$level] Monitoring Agent Alert",
            "description": "$message",
            "color": $color,
            "fields": [
                {
                    "name": "Host",
                    "value": "$hostname",
                    "inline": true
                },
                {
                    "name": "Component",
                    "value": "$component",
                    "inline": true
                },
                {
                    "name": "Time",
                    "value": "$timestamp",
                    "inline": false
                }
            ],
            "footer": {
                "text": "Monitoring Agent Alert System"
            }
        }
    ]
}
EOF
)
    
    curl -X POST \
         -H "Content-Type: application/json" \
         -d "$discord_payload" \
         "${DISCORD_WEBHOOK_URL}" \
         --connect-timeout 10 \
         --max-time 30 \
         --silent \
         >/dev/null 2>&1 || log_event "WARN" "ALERT" "Discord alert failed"
}

# Microsoft Teams alert function
send_teams_alert() {
    local level="$1"
    local component="$2"
    local message="$3"
    local hostname="$4"
    local timestamp="$5"
    
    local color
    case "$level" in
        "CRITICAL") color="FF0000" ;;  # Red
        "ERROR") color="FF0000" ;;     # Red
        "WARN") color="FFFF00" ;;      # Yellow
        *) color="00FF00" ;;           # Green
    esac
    
    local teams_payload=$(cat << EOF
{
    "@type": "MessageCard",
    "@context": "https://schema.org/extensions",
    "summary": "[$level] Monitoring Agent Alert",
    "themeColor": "$color",
    "sections": [
        {
            "activityTitle": "[$level] Monitoring Agent Alert",
            "activitySubtitle": "$hostname",
            "facts": [
                {
                    "name": "Component",
                    "value": "$component"
                },
                {
                    "name": "Message",
                    "value": "$message"
                },
                {
                    "name": "Time",
                    "value": "$timestamp"
                }
            ]
        }
    ]
}
EOF
)
    
    curl -X POST \
         -H "Content-Type: application/json" \
         -d "$teams_payload" \
         "${TEAMS_WEBHOOK_URL}" \
         --connect-timeout 10 \
         --max-time 30 \
         --silent \
         >/dev/null 2>&1 || log_event "WARN" "ALERT" "Teams alert failed"
}

# Log rotation function
rotate_logs() {
    local max_size=${MAX_LOG_SIZE:-104857600}  # 100MB
    local max_files=${MAX_LOG_FILES:-10}
    
    for log_file in "$MAIN_LOG" "$ALERT_LOG" "$METRICS_LOG"; do
        if [[ -f "$log_file" ]]; then
            local file_size=$(stat -f%z "$log_file" 2>/dev/null || stat -c%s "$log_file" 2>/dev/null || echo 0)
            
            if [[ $file_size -gt $max_size ]]; then
                log_event "INFO" "SYSTEM" "Rotating log file: $log_file (size: $file_size bytes)"
                
                # Rotate existing files
                for ((i=max_files-1; i>=1; i--)); do
                    local old_file="${log_file}.${i}"
                    local new_file="${log_file}.$((i+1))"
                    if [[ -f "$old_file" ]]; then
                        mv "$old_file" "$new_file"
                    fi
                done
                
                # Move current log to .1
                mv "$log_file" "${log_file}.1"
                
                # Create new log file
                touch "$log_file"
                chmod 640 "$log_file"
                
                # Remove old files beyond limit
                for ((i=max_files+1; i<=20; i++)); do
                    local old_file="${log_file}.${i}"
                    if [[ -f "$old_file" ]]; then
                        rm -f "$old_file"
                    fi
                done
            fi
        fi
    done
}

# Send heartbeat
send_heartbeat() {
    local uptime=$(uptime)
    local process_count=0
    
    for daemon in monitoring-agentd monitoring-execd monitoring-modulesd monitoring-logcollector monitoring-syscheckd; do
        if pgrep -f "$daemon" > /dev/null; then
            process_count=$((process_count + 1))
        fi
    done
    
    log_event "INFO" "HEARTBEAT" "System healthy - $process_count/5 processes running - $uptime"
}

# Generate health report
generate_health_report() {
    local report_file="${LOG_DIR}/health-report-$(date +%Y%m%d-%H%M%S).log"
    
    {
        echo "=== Monitoring Agent Health Report ==="
        echo "Generated: $(date)"
        echo "Host: $(hostname)"
        echo ""
        
        echo "=== System Information ==="
        echo "Uptime: $(uptime)"
        echo "Load Average: $(uptime | awk -F'load average:' '{print $2}')"
        echo "Memory: $(free -h | awk '/^Mem:/ {print $3"/"$2" ("$3/$2*100"%)"}')"
        echo "Disk Usage: $(df "${AGENT_HOME}" | awk 'NR==2 {print $3"/"$2" ("$5")"}')"
        echo ""
        
        echo "=== Process Status ==="
        for daemon in monitoring-agentd monitoring-execd monitoring-modulesd monitoring-logcollector monitoring-syscheckd; do
            if pgrep -f "$daemon" > /dev/null; then
                echo "✓ $daemon: RUNNING"
            else
                echo "✗ $daemon: STOPPED"
            fi
        done
        echo ""
        
        echo "=== Recent Alerts ==="
        if [[ -f "$ALERT_LOG" ]]; then
            tail -20 "$ALERT_LOG"
        else
            echo "No recent alerts"
        fi
        echo ""
        
        echo "=== Log File Sizes ==="
        for log_file in "$MAIN_LOG" "$ALERT_LOG" "$METRICS_LOG"; do
            if [[ -f "$log_file" ]]; then
                local size=$(stat -f%z "$log_file" 2>/dev/null || stat -c%s "$log_file" 2>/dev/null || echo 0)
                echo "$(basename "$log_file"): $((size / 1024 / 1024))MB"
            fi
        done
        
    } > "$report_file"
    
    log_event "INFO" "SYSTEM" "Health report generated: $report_file"
}

# Main monitoring loop
main_loop() {
    local last_metrics=0
    local last_heartbeat=0
    local last_rotation=0
    local metrics_interval=300      # 5 minutes
    local heartbeat_interval=${HEARTBEAT_INTERVAL:-3600}  # 1 hour
    local rotation_interval=3600    # 1 hour
    
    log_event "INFO" "MONITORING" "Enhanced logging and alerting system started"
    
    while true; do
        local current_time=$(date +%s)
        
        # Log metrics
        if [[ $((current_time - last_metrics)) -gt $metrics_interval ]]; then
            log_metrics
            last_metrics=$current_time
        fi
        
        # Send heartbeat
        if [[ $((current_time - last_heartbeat)) -gt $heartbeat_interval ]]; then
            send_heartbeat
            last_heartbeat=$current_time
        fi
        
        # Rotate logs
        if [[ $((current_time - last_rotation)) -gt $rotation_interval ]]; then
            rotate_logs
            last_rotation=$current_time
        fi
        
        # Check for health report generation (daily at 00:00)
        if [[ $(date +%H%M) == "0000" ]]; then
            generate_health_report
        fi
        
        sleep 60  # Check every minute
    done
}

# Command line interface
case "${1:-start}" in
    start)
        init_config
        mkdir -p "$LOG_DIR" "$STATE_DIR"
        main_loop
        ;;
    stop)
        pkill -f "monitoring-logging.sh" || true
        log_event "INFO" "MONITORING" "Enhanced logging and alerting system stopped"
        ;;
    test-alert)
        init_config
        log_event "WARN" "TEST" "This is a test alert to verify notification systems"
        ;;
    rotate)
        init_config
        rotate_logs
        ;;
    config)
        echo "Current configuration file: $CONFIG_FILE"
        if [[ -f "$CONFIG_FILE" ]]; then
            cat "$CONFIG_FILE"
        else
            echo "Configuration file not found. Run with 'start' to create default configuration."
        fi
        ;;
    *)
        echo "Usage: $0 {start|stop|test-alert|rotate|config}"
        echo ""
        echo "Commands:"
        echo "  start      - Start the logging and alerting system"
        echo "  stop       - Stop the logging and alerting system"
        echo "  test-alert - Send a test alert"
        echo "  rotate     - Manually rotate log files"
        echo "  config     - Show current configuration"
        exit 1
        ;;
esac