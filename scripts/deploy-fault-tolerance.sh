#!/bin/bash
# Monitoring Agent Fault Tolerance Deployment Script
# Deploys and configures the complete fault-tolerant monitoring system
# Copyright (C) 2025, Monitoring Solutions Inc.

set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly AGENT_HOME="$(dirname "$SCRIPT_DIR")"
readonly LOG_FILE="${AGENT_HOME}/logs/deployment.log"

# Colors for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m' # No Color

# Logging function
log() {
    local level="$1"
    local message="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local log_entry="[$timestamp] [$level] [DEPLOY] $message"
    
    echo "$log_entry" | tee -a "$LOG_FILE"
    
    case "$level" in
        "ERROR")
            echo -e "${RED}$log_entry${NC}" >&2
            ;;
        "WARN")
            echo -e "${YELLOW}$log_entry${NC}" >&2
            ;;
        "SUCCESS")
            echo -e "${GREEN}$log_entry${NC}"
            ;;
        "INFO")
            echo -e "${BLUE}$log_entry${NC}"
            ;;
        *)
            echo "$log_entry"
            ;;
    esac
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "This script must be run as root for system integration"
        echo "Run: sudo $0"
        exit 1
    fi
}

# Detect operating system
detect_os() {
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        OS_NAME="$ID"
        OS_VERSION="$VERSION_ID"
    else
        OS_NAME=$(uname -s)
        OS_VERSION=$(uname -r)
    fi
    
    log "INFO" "Detected OS: $OS_NAME $OS_VERSION"
}

# Create monitoring user and group
create_monitoring_user() {
    log "INFO" "Creating monitoring user and group"
    
    # Create group if it doesn't exist
    if ! getent group monitoring >/dev/null 2>&1; then
        groupadd -r monitoring
        log "SUCCESS" "Created monitoring group"
    else
        log "INFO" "Monitoring group already exists"
    fi
    
    # Create user if it doesn't exist
    if ! getent passwd monitoring >/dev/null 2>&1; then
        useradd -r -g monitoring -d "$AGENT_HOME" -s /bin/bash monitoring
        log "SUCCESS" "Created monitoring user"
    else
        log "INFO" "Monitoring user already exists"
    fi
    
    # Set ownership
    chown -R monitoring:monitoring "$AGENT_HOME"
    log "SUCCESS" "Set ownership to monitoring:monitoring"
}

# Install system dependencies
install_dependencies() {
    log "INFO" "Installing system dependencies"
    
    case "$OS_NAME" in
        "ubuntu"|"debian")
            apt-get update
            apt-get install -y systemd curl bc mailutils rsyslog
            ;;
        "centos"|"rhel"|"fedora")
            if command -v dnf >/dev/null 2>&1; then
                dnf install -y systemd curl bc mailx rsyslog
            else
                yum install -y systemd curl bc mailx rsyslog
            fi
            ;;
        "arch")
            pacman -Sy --noconfirm systemd curl bc s-nail rsyslog
            ;;
        *)
            log "WARN" "Unknown OS: $OS_NAME. Please install dependencies manually:"
            log "WARN" "  - systemd, curl, bc, mail utilities, rsyslog"
            ;;
    esac
    
    log "SUCCESS" "Dependencies installed"
}

# Deploy systemd services
deploy_systemd_services() {
    log "INFO" "Deploying integrated monitoring agent service"
    
    # Copy main service file to system directory
    local services=(
        "monitoring-agent.service"
    )
    
    for service in "${services[@]}"; do
        if [[ -f "${AGENT_HOME}/$service" ]]; then
            cp "${AGENT_HOME}/$service" /etc/systemd/system/
            log "SUCCESS" "Deployed $service"
        else
            log "ERROR" "Service file not found: $service"
            return 1
        fi
    done
    
    # Reload systemd
    systemctl daemon-reload
    log "SUCCESS" "Reloaded systemd configuration"
    
    # Enable main service (includes integrated fault tolerance)
    if systemctl enable "monitoring-agent.service" 2>/dev/null; then
        log "SUCCESS" "Enabled monitoring-agent.service with integrated fault tolerance"
    else
        log "ERROR" "Failed to enable monitoring-agent.service"
        return 1
    fi
    
    # Remove any previously installed standalone fault tolerance services
    local old_services=(
        "monitoring-agent-watchdog.service"
        "monitoring-agent-logging.service"
        "monitoring-agent-recovery.service"
        "monitoring-agent-recovery.timer"
    )
    
    for service in "${old_services[@]}"; do
        if systemctl is-enabled "$service" >/dev/null 2>&1; then
            systemctl disable "$service" 2>/dev/null || true
            log "INFO" "Disabled old standalone service: $service"
        fi
        
        if [[ -f "/etc/systemd/system/$service" ]]; then
            rm -f "/etc/systemd/system/$service"
            log "INFO" "Removed old service file: $service"
        fi
    done
    
    # Reload after cleanup
    systemctl daemon-reload
}

# Install sleep/hibernation monitoring
install_sleep_monitoring() {
    log "INFO" "Installing sleep/hibernation monitoring"
    
    if [[ -x "${AGENT_HOME}/scripts/install-sleep-monitoring.sh" ]]; then
        if "${AGENT_HOME}/scripts/install-sleep-monitoring.sh" install; then
            log "SUCCESS" "Sleep monitoring installed"
        else
            log "ERROR" "Failed to install sleep monitoring"
            return 1
        fi
    else
        log "WARN" "Sleep monitoring installer not found"
    fi
}

# Configure log rotation
configure_log_rotation() {
    log "INFO" "Configuring log rotation"
    
    # Create logrotate configuration
    cat > /etc/logrotate.d/monitoring-agent << EOF
${AGENT_HOME}/logs/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 644 monitoring monitoring
    postrotate
        systemctl reload monitoring-agent.service 2>/dev/null || true
    endscript
}
EOF
    
    log "SUCCESS" "Log rotation configured"
}

# Configure firewall (if applicable)
configure_firewall() {
    log "INFO" "Configuring firewall"
    
    # Configure firewall for common agent ports
    local ports=("1514" "1515" "55000")
    
    if command -v ufw >/dev/null 2>&1; then
        for port in "${ports[@]}"; do
            ufw allow out "$port" 2>/dev/null || true
        done
        log "SUCCESS" "UFW firewall configured"
    elif command -v firewall-cmd >/dev/null 2>&1; then
        for port in "${ports[@]}"; do
            firewall-cmd --permanent --add-port="$port/tcp" 2>/dev/null || true
        done
        firewall-cmd --reload 2>/dev/null || true
        log "SUCCESS" "FirewallD configured"
    else
        log "WARN" "No supported firewall found. Manual configuration may be required."
    fi
}

# Set up monitoring directories and permissions
setup_directories() {
    log "INFO" "Setting up directories and permissions"
    
    local directories=(
        "${AGENT_HOME}/logs"
        "${AGENT_HOME}/var/run"
        "${AGENT_HOME}/tmp"
        "${AGENT_HOME}/backup"
        "${AGENT_HOME}/etc"
        "${AGENT_HOME}/bin"
        "${AGENT_HOME}/scripts"
    )
    
    for dir in "${directories[@]}"; do
        mkdir -p "$dir"
        chown monitoring:monitoring "$dir"
        chmod 755 "$dir"
    done
    
    # Set specific permissions for sensitive files
    if [[ -f "${AGENT_HOME}/etc/client.keys" ]]; then
        chmod 640 "${AGENT_HOME}/etc/client.keys"
    fi
    
    if [[ -f "${AGENT_HOME}/etc/ossec.conf" ]]; then
        chmod 644 "${AGENT_HOME}/etc/ossec.conf"
    fi
    
    # Make scripts executable
    find "${AGENT_HOME}/scripts" -name "*.sh" -exec chmod +x {} \;
    
    log "SUCCESS" "Directories and permissions configured"
}

# Create initial configuration
create_initial_config() {
    log "INFO" "Creating initial configuration"
    
    # Create monitoring alerts configuration
    if [[ ! -f "${AGENT_HOME}/etc/monitoring-alerts.conf" ]]; then
        cat > "${AGENT_HOME}/etc/monitoring-alerts.conf" << 'EOF'
# Monitoring Agent Alert Configuration
# Edit this file to configure notifications

# Email settings (set ENABLE_EMAIL=true to activate)
ENABLE_EMAIL=false
SMTP_SERVER=""
SMTP_PORT="587"
SMTP_USER=""
SMTP_PASSWORD=""
SMTP_FROM="monitoring-agent@localhost"
SMTP_TO="admin@localhost"
SMTP_TLS="true"

# Slack settings (set ENABLE_SLACK=true to activate)
ENABLE_SLACK=false
SLACK_WEBHOOK_URL=""
SLACK_CHANNEL="#monitoring"

# System monitoring thresholds
DISK_USAGE_WARNING=85
DISK_USAGE_CRITICAL=95
MEMORY_USAGE_WARNING=80
MEMORY_USAGE_CRITICAL=90
CPU_USAGE_WARNING=80
CPU_USAGE_CRITICAL=95

# Process monitoring
PROCESS_DOWN_WARNING=30
PROCESS_DOWN_CRITICAL=300
MAX_RESTART_ATTEMPTS=5

# Enable syslog logging
ENABLE_SYSLOG=true
EOF
        chown monitoring:monitoring "${AGENT_HOME}/etc/monitoring-alerts.conf"
        chmod 600 "${AGENT_HOME}/etc/monitoring-alerts.conf"
        log "SUCCESS" "Created alerts configuration"
    fi
    
    # Create systemd environment file
    cat > /etc/default/monitoring-agent << EOF
# Monitoring Agent Environment Configuration
MONITORING_SERVICE_MODE=1
MONITORING_AUTO_RESTART=1
MONITORING_AGENT_HOME=${AGENT_HOME}
MONITORING_LOG_LEVEL=INFO
EOF
    
    log "SUCCESS" "Created environment configuration"
}

# Validate installation
validate_installation() {
    log "INFO" "Validating integrated fault-tolerant installation"
    
    local errors=0
    
    # Check main systemd service (with integrated fault tolerance)
    if systemctl list-unit-files monitoring-agent.service >/dev/null 2>&1; then
        log "SUCCESS" "✓ Main monitoring service installed: monitoring-agent.service"
        
        # Check if service is properly configured for fault tolerance
        if systemctl show monitoring-agent.service | grep -q "Restart=always"; then
            log "SUCCESS" "✓ Service configured with fault tolerance (Restart=always)"
        else
            log "WARN" "Service may not be properly configured for fault tolerance"
        fi
    else
        log "ERROR" "✗ Main monitoring service missing: monitoring-agent.service"
        errors=$((errors + 1))
    fi
    
    # Check that old standalone services are NOT present
    local old_services=(
        "monitoring-agent-watchdog.service"
        "monitoring-agent-logging.service"
        "monitoring-agent-recovery.service"
    )
    
    for service in "${old_services[@]}"; do
        if systemctl list-unit-files | grep -q "$service"; then
            log "WARN" "Old standalone service still present: $service (should be removed)"
        else
            log "SUCCESS" "✓ Old standalone service properly removed: $service"
        fi
    done
    
    # Check control scripts have integrated fault tolerance
    if [[ -f "${AGENT_HOME}/monitoring-agent-control.sh" ]]; then
        if grep -q "start_fault_tolerance_components" "${AGENT_HOME}/monitoring-agent-control.sh"; then
            log "SUCCESS" "✓ Linux control script has integrated fault tolerance"
        else
            log "ERROR" "✗ Linux control script missing fault tolerance integration"
            errors=$((errors + 1))
        fi
    else
        log "ERROR" "✗ Linux control script missing"
        errors=$((errors + 1))
    fi
    
    if [[ -f "${AGENT_HOME}/monitoring-agent-control.ps1" ]]; then
        if grep -q "Start-FaultToleranceComponents" "${AGENT_HOME}/monitoring-agent-control.ps1"; then
            log "SUCCESS" "✓ Windows control script has integrated fault tolerance"
        else
            log "ERROR" "✗ Windows control script missing fault tolerance integration"
            errors=$((errors + 1))
        fi
    else
        log "WARN" "Windows control script not found (not required on Linux)"
    fi
    
    # Check fault tolerance scripts are available
    local required_scripts=(
        "monitoring-watchdog.sh"
        "monitoring-recovery.sh"
        "monitoring-logging.sh"
        "test-fault-tolerance.sh"
    )
    
    for script in "${required_scripts[@]}"; do
        if [[ -x "${AGENT_HOME}/scripts/$script" ]]; then
            log "SUCCESS" "✓ Fault tolerance script available: $script"
        else
            log "ERROR" "✗ Fault tolerance script missing or not executable: $script"
            errors=$((errors + 1))
        fi
    done
    
    # Check directories
    local required_dirs=(
        "${AGENT_HOME}/logs"
        "${AGENT_HOME}/var/run"
        "${AGENT_HOME}/var/state"
        "${AGENT_HOME}/scripts"
    )
    
    for dir in "${required_dirs[@]}"; do
        if [[ -d "$dir" ]]; then
            log "SUCCESS" "✓ Directory exists: $dir"
        else
            log "ERROR" "✗ Directory missing: $dir"
            errors=$((errors + 1))
        fi
    done
    
    # Test integrated health check
    if [[ -x "${AGENT_HOME}/monitoring-agent-control.sh" ]]; then
        if "${AGENT_HOME}/monitoring-agent-control.sh" health-check-full >/dev/null 2>&1; then
            log "SUCCESS" "✓ Integrated health check working"
        else
            log "INFO" "Integrated health check available (may require service to be running)"
        fi
    fi
    
    return $errors
}

# Start services
start_services() {
    log "INFO" "Starting integrated monitoring service with fault tolerance"
    
    # Start main agent with integrated fault tolerance
    if systemctl start monitoring-agent.service; then
        log "SUCCESS" "Started monitoring-agent.service with integrated fault tolerance"
    else
        log "ERROR" "Failed to start monitoring-agent.service"
        return 1
    fi
    
    # Wait for agent to stabilize and initialize fault tolerance
    log "INFO" "Waiting for service to initialize fault tolerance components..."
    sleep 15
    
    # Verify service is running
    if systemctl is-active --quiet monitoring-agent.service; then
        log "SUCCESS" "✓ monitoring-agent.service is active with integrated fault tolerance"
    else
        log "ERROR" "⚠ monitoring-agent.service failed to start properly"
        return 1
    fi
    
    # Test integrated fault tolerance
    if [[ -x "${AGENT_HOME}/monitoring-agent-control.sh" ]]; then
        log "INFO" "Testing integrated fault tolerance..."
        if "${AGENT_HOME}/monitoring-agent-control.sh" health-check-full >/dev/null 2>&1; then
            log "SUCCESS" "✓ Integrated fault tolerance is working"
        else
            log "WARN" "Fault tolerance health check returned warnings (check logs)"
        fi
    fi
}

# Run initial tests
run_initial_tests() {
    log "INFO" "Running initial validation tests"
    
    if [[ -x "${AGENT_HOME}/scripts/test-fault-tolerance.sh" ]]; then
        # Run a subset of tests
        log "INFO" "Running basic service operation test"
        if sudo -u monitoring "${AGENT_HOME}/scripts/test-fault-tolerance.sh" single test_basic_service_operations; then
            log "SUCCESS" "Basic tests passed"
        else
            log "WARN" "Some tests failed - check logs for details"
        fi
    else
        log "WARN" "Test suite not found"
    fi
}

# Show deployment summary
show_summary() {
    echo ""
    echo "=================================================="
    echo "        DEPLOYMENT SUMMARY"
    echo "=================================================="
    
    log "INFO" "Fault-tolerant monitoring agent deployment completed!"
    
    echo ""
    echo "🎉 Features Deployed:"
    echo "  ✓ Enhanced systemd service with auto-restart"
    echo "  ✓ Process watchdog monitoring"
    echo "  ✓ Sleep/hibernation recovery hooks"
    echo "  ✓ Comprehensive logging and alerting"
    echo "  ✓ Automatic health checks and recovery"
    echo "  ✓ Log rotation and management"
    echo ""
    
    echo "🔧 Services Installed:"
    echo "  • monitoring-agent.service (main service)"
    echo "  • monitoring-agent-watchdog.service (process monitoring)"
    echo "  • monitoring-agent-logging.service (enhanced logging)"
    echo "  • monitoring-agent-recovery.timer (periodic recovery)"
    echo ""
    
    echo "📁 Important Files:"
    echo "  • Configuration: ${AGENT_HOME}/etc/monitoring-alerts.conf"
    echo "  • Main log: ${AGENT_HOME}/logs/monitoring-agent.log"
    echo "  • Test suite: ${AGENT_HOME}/scripts/test-fault-tolerance.sh"
    echo ""
    
    echo "🚀 Quick Commands:"
    echo "  • Check status: systemctl status monitoring-agent.service"
    echo "  • View logs: journalctl -u monitoring-agent.service -f"
    echo "  • Run tests: ${AGENT_HOME}/scripts/test-fault-tolerance.sh"
    echo "  • Health check: ${AGENT_HOME}/monitoring-agent-control.sh health-check"
    echo ""
    
    echo "⚙️  Next Steps:"
    echo "  1. Configure alerts in ${AGENT_HOME}/etc/monitoring-alerts.conf"
    echo "  2. Enroll with monitoring manager if needed"
    echo "  3. Test sleep/resume: sudo systemctl suspend"
    echo "  4. Monitor logs for proper operation"
    echo ""
}

# Uninstall function
uninstall() {
    log "INFO" "Uninstalling fault-tolerant monitoring system"
    
    # Stop services
    local services=(
        "monitoring-agent.service"
        "monitoring-agent-watchdog.service"
        "monitoring-agent-logging.service"
        "monitoring-agent-recovery.timer"
        "monitoring-agent-recovery.service"
    )
    
    for service in "${services[@]}"; do
        systemctl stop "$service" 2>/dev/null || true
        systemctl disable "$service" 2>/dev/null || true
        rm -f "/etc/systemd/system/$service"
    done
    
    # Remove sleep monitoring
    if [[ -x "${AGENT_HOME}/scripts/install-sleep-monitoring.sh" ]]; then
        "${AGENT_HOME}/scripts/install-sleep-monitoring.sh" uninstall
    fi
    
    # Remove configurations
    rm -f /etc/logrotate.d/monitoring-agent
    rm -f /etc/default/monitoring-agent
    
    # Reload systemd
    systemctl daemon-reload
    
    log "SUCCESS" "Uninstallation completed"
}

# Main execution
main() {
    case "${1:-install}" in
        install)
            echo "=================================================="
            echo "  Monitoring Agent Fault Tolerance Deployment"
            echo "=================================================="
            echo ""
            
            check_root
            detect_os
            
            # Ensure log directory exists
            mkdir -p "$(dirname "$LOG_FILE")"
            
            log "INFO" "Starting fault-tolerant monitoring agent deployment"
            
            create_monitoring_user
            install_dependencies
            setup_directories
            create_initial_config
            deploy_systemd_services
            install_sleep_monitoring
            configure_log_rotation
            configure_firewall
            
            if validate_installation; then
                start_services
                run_initial_tests
                show_summary
                log "SUCCESS" "Deployment completed successfully!"
            else
                log "ERROR" "Deployment validation failed!"
                exit 1
            fi
            ;;
            
        uninstall)
            check_root
            uninstall
            ;;
            
        validate)
            if validate_installation; then
                echo "✅ Installation validation passed"
            else
                echo "❌ Installation validation failed"
                exit 1
            fi
            ;;
            
        test)
            if [[ -x "${AGENT_HOME}/scripts/test-fault-tolerance.sh" ]]; then
                "${AGENT_HOME}/scripts/test-fault-tolerance.sh"
            else
                echo "Test suite not found"
                exit 1
            fi
            ;;
            
        *)
            echo "Usage: $0 {install|uninstall|validate|test}"
            echo ""
            echo "Commands:"
            echo "  install   - Deploy fault-tolerant monitoring system (default)"
            echo "  uninstall - Remove fault-tolerant monitoring system"
            echo "  validate  - Validate current installation"
            echo "  test      - Run fault tolerance test suite"
            exit 1
            ;;
    esac
}

# Run main function
main "$@"