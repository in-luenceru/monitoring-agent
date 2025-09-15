#!/bin/bash

# Monitoring Agent Security Hardening Script
# Copyright (C) 2025, Monitoring Solutions Inc.
# Version: 1.0.0

set -euo pipefail

# Configuration
readonly AGENT_HOME="/home/anandhu/monitor"
readonly AGENT_USER="monitoring"
readonly AGENT_GROUP="monitoring"
readonly LOG_FILE="${AGENT_HOME}/logs/security-hardening.log"

# Colors for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m'

# Logging function
log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [$level] $message" >> "$LOG_FILE"
    
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
    esac
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log "ERROR" "This script must be run as root for proper security hardening"
        exit 1
    fi
}

# Create monitoring user and group
create_monitoring_user() {
    log "INFO" "Creating monitoring user and group..."
    
    # Create group
    if ! getent group "$AGENT_GROUP" >/dev/null 2>&1; then
        groupadd -r "$AGENT_GROUP"
        log "INFO" "Created group: $AGENT_GROUP"
    else
        log "INFO" "Group $AGENT_GROUP already exists"
    fi
    
    # Create user
    if ! getent passwd "$AGENT_USER" >/dev/null 2>&1; then
        useradd -r -g "$AGENT_GROUP" -d "$AGENT_HOME" -s /bin/false -c "Monitoring Agent User" "$AGENT_USER"
        log "INFO" "Created user: $AGENT_USER"
    else
        log "INFO" "User $AGENT_USER already exists"
    fi
}

# Set secure file permissions
set_file_permissions() {
    log "INFO" "Setting secure file permissions..."
    
    # Ensure agent home exists
    mkdir -p "$AGENT_HOME"
    
    # Set ownership
    chown -R root:root "$AGENT_HOME"
    chown -R "$AGENT_USER:$AGENT_GROUP" "$AGENT_HOME/logs" 2>/dev/null || true
    chown -R "$AGENT_USER:$AGENT_GROUP" "$AGENT_HOME/queue" 2>/dev/null || true
    chown -R "$AGENT_USER:$AGENT_GROUP" "$AGENT_HOME/var" 2>/dev/null || true
    chown -R "$AGENT_USER:$AGENT_GROUP" "$AGENT_HOME/tmp" 2>/dev/null || true
    
    # Set directory permissions
    chmod 755 "$AGENT_HOME"
    chmod 750 "$AGENT_HOME/bin" 2>/dev/null || true
    chmod 750 "$AGENT_HOME/etc" 2>/dev/null || true
    chmod 750 "$AGENT_HOME/logs" 2>/dev/null || true
    chmod 750 "$AGENT_HOME/var" 2>/dev/null || true
    chmod 700 "$AGENT_HOME/queue" 2>/dev/null || true
    chmod 700 "$AGENT_HOME/tmp" 2>/dev/null || true
    
    # Set binary permissions
    if [[ -d "$AGENT_HOME/bin" ]]; then
        chmod 755 "$AGENT_HOME/bin/"* 2>/dev/null || true
    fi
    
    # Set configuration file permissions
    if [[ -f "$AGENT_HOME/etc/ossec.conf" ]]; then
        chmod 640 "$AGENT_HOME/etc/ossec.conf"
        chown root:"$AGENT_GROUP" "$AGENT_HOME/etc/ossec.conf"
    fi
    
    # Set client keys permissions
    if [[ -f "$AGENT_HOME/etc/client.keys" ]]; then
        chmod 600 "$AGENT_HOME/etc/client.keys"
        chown "$AGENT_USER:$AGENT_GROUP" "$AGENT_HOME/etc/client.keys"
    fi
    
    # Set log file permissions
    find "$AGENT_HOME/logs" -type f -name "*.log" -exec chmod 640 {} \; 2>/dev/null || true
    find "$AGENT_HOME/logs" -type f -name "*.log" -exec chown "$AGENT_USER:$AGENT_GROUP" {} \; 2>/dev/null || true
    
    log "INFO" "File permissions set successfully"
}

# Configure AppArmor or SELinux
configure_mandatory_access_control() {
    log "INFO" "Configuring mandatory access control..."
    
    # Check for SELinux
    if command -v getenforce >/dev/null 2>&1; then
        if [[ "$(getenforce)" == "Enforcing" ]]; then
            log "INFO" "SELinux is enforcing - configuring contexts..."
            # Set SELinux contexts
            semanage fcontext -a -t admin_home_t "$AGENT_HOME" 2>/dev/null || true
            semanage fcontext -a -t bin_t "$AGENT_HOME/bin(/.*)?" 2>/dev/null || true
            semanage fcontext -a -t etc_t "$AGENT_HOME/etc(/.*)?" 2>/dev/null || true
            semanage fcontext -a -t var_log_t "$AGENT_HOME/logs(/.*)?" 2>/dev/null || true
            restorecon -R "$AGENT_HOME" 2>/dev/null || true
        fi
    fi
    
    # Check for AppArmor
    if command -v aa-status >/dev/null 2>&1; then
        log "INFO" "AppArmor detected - creating profile..."
        
        # Create basic AppArmor profile
        cat > "/etc/apparmor.d/monitoring-agent" << 'EOF'
#include <tunables/global>

/home/anandhu/monitor/bin/monitoring-agentd {
  #include <abstractions/base>
  #include <abstractions/nameservice>
  
  capability net_admin,
  capability sys_ptrace,
  capability dac_override,
  
  network inet stream,
  network inet dgram,
  
  /home/anandhu/monitor/** r,
  /home/anandhu/monitor/bin/** ix,
  /home/anandhu/monitor/etc/** r,
  /home/anandhu/monitor/logs/** rw,
  /home/anandhu/monitor/queue/** rw,
  /home/anandhu/monitor/var/** rw,
  /home/anandhu/monitor/tmp/** rw,
  
  /proc/*/stat r,
  /proc/*/cmdline r,
  /proc/sys/kernel/hostname r,
  
  /var/log/** r,
  /etc/passwd r,
  /etc/group r,
  
  # Deny access to sensitive areas
  deny /home/** r,
  deny /root/** r,
  deny /tmp/** w,
  deny /var/tmp/** w,
}
EOF
        
        # Load the profile
        apparmor_parser -r /etc/apparmor.d/monitoring-agent 2>/dev/null || true
    fi
}

# Configure system limits
configure_system_limits() {
    log "INFO" "Configuring system resource limits..."
    
    # Create limits configuration for monitoring user
    cat > "/etc/security/limits.d/monitoring-agent.conf" << EOF
# Monitoring Agent resource limits
$AGENT_USER soft nofile 65536
$AGENT_USER hard nofile 65536
$AGENT_USER soft nproc 32768
$AGENT_USER hard nproc 32768
$AGENT_USER soft memlock unlimited
$AGENT_USER hard memlock unlimited
EOF
    
    log "INFO" "System limits configured"
}

# Configure log rotation
configure_log_rotation() {
    log "INFO" "Configuring log rotation..."
    
    cat > "/etc/logrotate.d/monitoring-agent" << EOF
$AGENT_HOME/logs/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 640 $AGENT_USER $AGENT_GROUP
    postrotate
        /bin/systemctl reload monitoring-agent.service > /dev/null 2>&1 || true
    endscript
}
EOF
    
    log "INFO" "Log rotation configured"
}

# Configure sysctl parameters
configure_sysctl() {
    log "INFO" "Configuring kernel parameters..."
    
    cat > "/etc/sysctl.d/99-monitoring-agent.conf" << 'EOF'
# Monitoring Agent security settings
# Disable IP forwarding
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# Enable source route verification
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Disable ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Disable source routed packets
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Log suspicious packets
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# Increase inotify limits for file monitoring
fs.inotify.max_user_watches = 524288
fs.inotify.max_user_instances = 512

# Kernel security
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 2
kernel.yama.ptrace_scope = 1
EOF
    
    # Apply the settings
    sysctl -p /etc/sysctl.d/99-monitoring-agent.conf 2>/dev/null || true
    
    log "INFO" "Kernel parameters configured"
}

# Configure firewall rules
configure_firewall() {
    log "INFO" "Configuring firewall rules..."
    
    # Detect firewall and configure accordingly
    if command -v ufw >/dev/null 2>&1; then
        log "INFO" "Configuring UFW firewall..."
        ufw --force enable
        ufw default deny incoming
        ufw default allow outgoing
        # Allow outbound connections to Wazuh manager (will be configured during enrollment)
        
    elif command -v firewall-cmd >/dev/null 2>&1; then
        log "INFO" "Configuring firewalld..."
        systemctl enable firewalld
        systemctl start firewalld
        firewall-cmd --set-default-zone=public
        
    elif command -v iptables >/dev/null 2>&1; then
        log "INFO" "Configuring iptables..."
        # Basic iptables rules
        iptables -F
        iptables -P INPUT DROP
        iptables -P FORWARD DROP
        iptables -P OUTPUT ACCEPT
        
        # Allow loopback
        iptables -A INPUT -i lo -j ACCEPT
        iptables -A INPUT -o lo -j ACCEPT
        
        # Allow established connections
        iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
        
        # Save rules (method varies by distribution)
        if command -v iptables-save >/dev/null 2>&1; then
            iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
        fi
    fi
    
    log "INFO" "Firewall configured"
}

# Setup monitoring and alerting
setup_monitoring() {
    log "INFO" "Setting up monitoring and alerting..."
    
    # Create monitoring script
    cat > "$AGENT_HOME/bin/monitoring-health-check.sh" << 'EOF'
#!/bin/bash

# Health check script for Monitoring Agent
AGENT_HOME="/home/anandhu/monitor"
ALERT_EMAIL="admin@monitoring-solutions.com"

# Check if agent is running
if ! pgrep -f "monitoring-agentd" > /dev/null; then
    echo "CRITICAL: Monitoring Agent is not running" | \
    mail -s "ALERT: Monitoring Agent Down" "$ALERT_EMAIL" 2>/dev/null || \
    logger -p local0.crit "CRITICAL: Monitoring Agent is not running"
fi

# Check disk space
USAGE=$(df "$AGENT_HOME" | awk 'NR==2 {print $5}' | sed 's/%//')
if [ "$USAGE" -gt 90 ]; then
    echo "WARNING: High disk usage: ${USAGE}%" | \
    mail -s "ALERT: High Disk Usage" "$ALERT_EMAIL" 2>/dev/null || \
    logger -p local0.warning "WARNING: High disk usage: ${USAGE}%"
fi

# Check log file size
if [ -f "$AGENT_HOME/logs/monitoring-agent.log" ]; then
    SIZE=$(stat -c%s "$AGENT_HOME/logs/monitoring-agent.log")
    if [ "$SIZE" -gt 104857600 ]; then  # 100MB
        echo "WARNING: Large log file: $SIZE bytes" | \
        mail -s "ALERT: Large Log File" "$ALERT_EMAIL" 2>/dev/null || \
        logger -p local0.warning "WARNING: Large log file: $SIZE bytes"
    fi
fi
EOF
    
    chmod +x "$AGENT_HOME/bin/monitoring-health-check.sh"
    
    # Setup cron job for health checks
    cat > "/etc/cron.d/monitoring-agent" << EOF
# Monitoring Agent health checks
*/5 * * * * root $AGENT_HOME/bin/monitoring-health-check.sh > /dev/null 2>&1
EOF
    
    log "INFO" "Monitoring and alerting configured"
}

# Create backup and recovery procedures
setup_backup_recovery() {
    log "INFO" "Setting up backup and recovery procedures..."
    
    # Create backup script
    cat > "$AGENT_HOME/bin/monitoring-backup.sh" << 'EOF'
#!/bin/bash

AGENT_HOME="/home/anandhu/monitor"
BACKUP_DIR="/var/backups/monitoring-agent"
DATE=$(date +%Y%m%d_%H%M%S)

# Create backup directory
mkdir -p "$BACKUP_DIR"

# Create backup
tar -czf "$BACKUP_DIR/monitoring-agent-$DATE.tar.gz" \
    "$AGENT_HOME/etc" \
    "$AGENT_HOME/logs" \
    "$AGENT_HOME/var" 2>/dev/null || true

# Remove old backups (keep 30 days)
find "$BACKUP_DIR" -name "monitoring-agent-*.tar.gz" -mtime +30 -delete

echo "Backup created: $BACKUP_DIR/monitoring-agent-$DATE.tar.gz"
EOF
    
    chmod +x "$AGENT_HOME/bin/monitoring-backup.sh"
    
    # Setup daily backup cron job
    cat > "/etc/cron.d/monitoring-agent-backup" << EOF
# Daily backup of Monitoring Agent configuration
0 2 * * * root $AGENT_HOME/bin/monitoring-backup.sh > /dev/null 2>&1
EOF
    
    log "INFO" "Backup and recovery procedures configured"
}

# Harden SSH if agent uses it
harden_ssh() {
    if [[ -f "/etc/ssh/sshd_config" ]]; then
        log "INFO" "Hardening SSH configuration..."
        
        # Backup original config
        cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup.$(date +%Y%m%d)
        
        # Apply hardening settings
        sed -i 's/#PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
        sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
        sed -i 's/#PubkeyAuthentication yes/PubkeyAuthentication yes/' /etc/ssh/sshd_config
        sed -i 's/#Protocol 2/Protocol 2/' /etc/ssh/sshd_config
        
        # Add additional security settings
        if ! grep -q "AllowUsers monitoring" /etc/ssh/sshd_config; then
            echo "AllowUsers monitoring" >> /etc/ssh/sshd_config
        fi
        
        # Restart SSH service
        systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true
        
        log "INFO" "SSH hardening completed"
    fi
}

# Main execution
main() {
    log "INFO" "Starting Monitoring Agent security hardening..."
    
    # Ensure log directory exists
    mkdir -p "$(dirname "$LOG_FILE")"
    
    check_root
    create_monitoring_user
    set_file_permissions
    configure_mandatory_access_control
    configure_system_limits
    configure_log_rotation
    configure_sysctl
    configure_firewall
    setup_monitoring
    setup_backup_recovery
    harden_ssh
    
    log "INFO" "Security hardening completed successfully"
    echo ""
    echo -e "${GREEN}Security hardening completed successfully!${NC}"
    echo "Next steps:"
    echo "1. Review the configuration files"
    echo "2. Test the agent functionality"
    echo "3. Configure monitoring alerts"
    echo "4. Enroll the agent with your manager"
}

# Run main function
main "$@"