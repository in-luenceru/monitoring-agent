#!/bin/bash
# Monitoring Agent Sleep/Resume Installation Script
# Installs system hooks for sleep/hibernate/resume events
# Copyright (C) 2025, Monitoring Solutions Inc.

set -euo pipefail

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly AGENT_HOME="$(dirname "$SCRIPT_DIR")"
readonly LOG_FILE="${AGENT_HOME}/logs/monitoring-agent.log"

# System sleep hook paths
readonly SYSTEMD_SLEEP_DIR="/lib/systemd/system-sleep"
readonly SLEEP_HOOK_NAME="50-monitoring-agent"
readonly SLEEP_HOOK_PATH="${SYSTEMD_SLEEP_DIR}/${SLEEP_HOOK_NAME}"

# Logging function
log() {
    local level="$1"
    local message="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [$level] [SLEEP-INSTALL] $message" | tee -a "$LOG_FILE"
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "This script must be run as root for system integration"
        echo "Run: sudo $0"
        exit 1
    fi
}

# Install systemd sleep hooks
install_sleep_hooks() {
    log "INFO" "Installing systemd sleep/resume hooks"
    
    # Create systemd sleep directory if it doesn't exist
    if [[ ! -d "$SYSTEMD_SLEEP_DIR" ]]; then
        log "INFO" "Creating systemd sleep directory: $SYSTEMD_SLEEP_DIR"
        mkdir -p "$SYSTEMD_SLEEP_DIR"
    fi
    
    # Create the sleep hook script
    cat > "$SLEEP_HOOK_PATH" << 'EOF'
#!/bin/bash
# Monitoring Agent Sleep/Resume Hook for systemd
# This script is called by systemd on sleep/resume events

set -euo pipefail

# Source the monitoring agent's sleep hook
MONITORING_SLEEP_HOOK="/home/anandhu/monitor/scripts/monitoring-sleep-hook"

if [[ -x "$MONITORING_SLEEP_HOOK" ]]; then
    "$MONITORING_SLEEP_HOOK" "$@"
else
    logger -t monitoring-agent-sleep "Sleep hook not found: $MONITORING_SLEEP_HOOK"
fi
EOF
    
    # Make the hook executable
    chmod +x "$SLEEP_HOOK_PATH"
    
    log "INFO" "✓ Systemd sleep hook installed: $SLEEP_HOOK_PATH"
}

# Create systemd service units for sleep/resume monitoring
install_sleep_services() {
    log "INFO" "Installing sleep/resume monitoring services"
    
    # Create resume-monitoring service
    cat > /etc/systemd/system/monitoring-agent-resume.service << EOF
[Unit]
Description=Monitoring Agent Resume Handler
After=suspend.target hibernate.target hybrid-sleep.target suspend-then-hibernate.target
StopWhenUnneeded=true

[Service]
Type=oneshot
User=monitoring
Group=monitoring
ExecStart=${AGENT_HOME}/scripts/monitoring-recovery.sh
TimeoutStartSec=120s
RemainAfterExit=false

# Security
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=${AGENT_HOME}

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=monitoring-resume

[Install]
WantedBy=suspend.target hibernate.target hybrid-sleep.target suspend-then-hibernate.target
EOF
    
    # Create wake-up timer
    cat > /etc/systemd/system/monitoring-agent-wakeup.timer << EOF
[Unit]
Description=Monitoring Agent Wake-up Health Check
Requires=monitoring-agent.service

[Timer]
OnBootSec=2min
OnWakeup=true
Persistent=true

[Install]
WantedBy=timers.target
EOF
    
    cat > /etc/systemd/system/monitoring-agent-wakeup.service << EOF
[Unit]
Description=Monitoring Agent Wake-up Health Check
After=monitoring-agent.service

[Service]
Type=oneshot
User=monitoring
Group=monitoring
ExecStart=${AGENT_HOME}/monitoring-agent-control.sh health-check
TimeoutStartSec=60s

# Security
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=${AGENT_HOME}

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=monitoring-wakeup
EOF
    
    # Reload systemd and enable services
    systemctl daemon-reload
    systemctl enable monitoring-agent-resume.service
    systemctl enable monitoring-agent-wakeup.timer
    systemctl start monitoring-agent-wakeup.timer
    
    log "INFO" "✓ Sleep/resume monitoring services installed and enabled"
}

# Install ACPI event handlers (for older systems)
install_acpi_handlers() {
    if [[ -d "/etc/acpi/events" ]]; then
        log "INFO" "Installing ACPI event handlers"
        
        # Create ACPI event for suspend
        cat > /etc/acpi/events/monitoring-suspend << EOF
event=button/sleep.*
action=${AGENT_HOME}/scripts/monitoring-sleep-hook pre suspend
EOF
        
        # Create ACPI event for resume (if supported)
        cat > /etc/acpi/events/monitoring-resume << EOF
event=ac_adapter.*
action=${AGENT_HOME}/scripts/monitoring-sleep-hook post resume
EOF
        
        # Restart ACPI daemon if running
        if systemctl is-active --quiet acpid; then
            systemctl restart acpid
            log "INFO" "✓ ACPI event handlers installed and acpid restarted"
        else
            log "INFO" "✓ ACPI event handlers installed (acpid not running)"
        fi
    else
        log "DEBUG" "ACPI events directory not found - skipping ACPI handlers"
    fi
}

# Install desktop environment specific handlers
install_desktop_handlers() {
    log "INFO" "Installing desktop environment handlers"
    
    # Create desktop file for session management
    local desktop_dir="/etc/xdg/autostart"
    if [[ -d "$desktop_dir" ]]; then
        cat > "${desktop_dir}/monitoring-agent-session.desktop" << EOF
[Desktop Entry]
Type=Application
Name=Monitoring Agent Session Handler
Comment=Handles monitoring agent session events
Exec=${AGENT_HOME}/scripts/monitoring-session-handler.sh
NoDisplay=true
X-GNOME-Autostart-enabled=true
X-KDE-autostart-enabled=true
X-MATE-Autostart-enabled=true
X-XFCE-Autostart-enabled=true
EOF
        
        log "INFO" "✓ Desktop session handler installed"
    fi
    
    # Create session handler script
    cat > "${AGENT_HOME}/scripts/monitoring-session-handler.sh" << 'EOF'
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
EOF
    
    chmod +x "${AGENT_HOME}/scripts/monitoring-session-handler.sh"
}

# Verify installation
verify_installation() {
    log "INFO" "Verifying sleep/resume monitoring installation"
    
    local errors=0
    
    # Check systemd hook
    if [[ -x "$SLEEP_HOOK_PATH" ]]; then
        log "INFO" "✓ Systemd sleep hook installed and executable"
    else
        log "ERROR" "✗ Systemd sleep hook not found or not executable"
        errors=$((errors + 1))
    fi
    
    # Check systemd services
    if systemctl is-enabled --quiet monitoring-agent-resume.service; then
        log "INFO" "✓ Resume service enabled"
    else
        log "ERROR" "✗ Resume service not enabled"
        errors=$((errors + 1))
    fi
    
    if systemctl is-enabled --quiet monitoring-agent-wakeup.timer; then
        log "INFO" "✓ Wakeup timer enabled"
    else
        log "ERROR" "✗ Wakeup timer not enabled"
        errors=$((errors + 1))
    fi
    
    # Test the monitoring hook
    if [[ -x "${AGENT_HOME}/scripts/monitoring-sleep-hook" ]]; then
        log "INFO" "✓ Monitoring sleep hook is executable"
    else
        log "ERROR" "✗ Monitoring sleep hook not found or not executable"
        errors=$((errors + 1))
    fi
    
    if [[ $errors -eq 0 ]]; then
        log "INFO" "✅ Sleep/resume monitoring installation verified successfully"
        return 0
    else
        log "ERROR" "❌ Sleep/resume monitoring installation has $errors errors"
        return 1
    fi
}

# Uninstall function
uninstall_sleep_monitoring() {
    log "INFO" "Uninstalling sleep/resume monitoring"
    
    # Remove systemd hooks
    rm -f "$SLEEP_HOOK_PATH"
    
    # Disable and remove systemd services
    systemctl disable monitoring-agent-resume.service 2>/dev/null || true
    systemctl disable monitoring-agent-wakeup.timer 2>/dev/null || true
    systemctl stop monitoring-agent-wakeup.timer 2>/dev/null || true
    
    rm -f /etc/systemd/system/monitoring-agent-resume.service
    rm -f /etc/systemd/system/monitoring-agent-wakeup.timer
    rm -f /etc/systemd/system/monitoring-agent-wakeup.service
    
    # Remove ACPI handlers
    rm -f /etc/acpi/events/monitoring-suspend
    rm -f /etc/acpi/events/monitoring-resume
    
    # Remove desktop handlers
    rm -f /etc/xdg/autostart/monitoring-agent-session.desktop
    rm -f "${AGENT_HOME}/scripts/monitoring-session-handler.sh"
    
    systemctl daemon-reload
    
    log "INFO" "✅ Sleep/resume monitoring uninstalled"
}

# Main function
main() {
    case "${1:-install}" in
        install)
            check_root
            log "INFO" "Installing sleep/resume monitoring for Monitoring Agent"
            
            install_sleep_hooks
            install_sleep_services
            install_acpi_handlers
            install_desktop_handlers
            
            if verify_installation; then
                log "INFO" "🎉 Sleep/resume monitoring installation completed successfully!"
                echo ""
                echo "Sleep/resume monitoring features installed:"
                echo "  ✓ Systemd sleep/hibernate/resume hooks"
                echo "  ✓ Automatic health checks after resume"
                echo "  ✓ Wake-up timer for periodic checks"
                echo "  ✓ ACPI event handlers (if supported)"
                echo "  ✓ Desktop session monitoring"
                echo ""
                echo "The monitoring agent will now automatically:"
                echo "  - Detect system sleep/hibernation events"
                echo "  - Verify agent health after resume"
                echo "  - Restart failed processes automatically"
                echo "  - Log all power-related events"
                echo ""
                echo "Test with: sudo systemctl suspend"
            else
                log "ERROR" "Installation completed with errors - check logs"
                exit 1
            fi
            ;;
        uninstall)
            check_root
            uninstall_sleep_monitoring
            ;;
        verify)
            verify_installation
            ;;
        *)
            echo "Usage: $0 [install|uninstall|verify]"
            echo ""
            echo "Commands:"
            echo "  install   - Install sleep/resume monitoring (default)"
            echo "  uninstall - Remove sleep/resume monitoring"
            echo "  verify    - Verify installation"
            exit 1
            ;;
    esac
}

# Ensure required directories exist
mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || true

# Run main function
main "$@"