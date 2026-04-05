#!/bin/bash

# Backup and Replace Monitoring Agent Files Script
# This script backs up existing files in the agent folder and replaces them 
# with updated files from the win32 folder based on the NSI installer file mappings

set -e  # Exit on any error

# Define paths
WIN32_DIR="/home/anandhu/Desktop/monitoring_agent/src/win32"
AGENT_DIR="/home/anandhu/Desktop/monitoring_agent/src/win32/agent"
BACKUP_DIR="/home/anandhu/Desktop/monitoring_agent/src/win32/agent/backup_$(date +%Y%m%d_%H%M%S)"

# Create backup directory
echo "Creating backup directory: $BACKUP_DIR"
mkdir -p "$BACKUP_DIR"

# Function to backup and replace a file
backup_and_replace() {
    local source_file="$1"
    local dest_file="$2"
    local backup_name="$3"
    
    # Check if source file exists
    if [[ ! -f "$source_file" ]]; then
        echo "WARNING: Source file not found: $source_file"
        return 1
    fi
    
    # Backup existing file if it exists
    if [[ -f "$dest_file" ]]; then
        echo "Backing up: $dest_file -> $BACKUP_DIR/$backup_name"
        cp "$dest_file" "$BACKUP_DIR/$backup_name"
    fi
    
    # Copy new file
    echo "Copying: $source_file -> $dest_file"
    cp "$source_file" "$dest_file"
}

echo "================================================"
echo "MONITORING AGENT FILES BACKUP AND REPLACEMENT"
echo "================================================"
echo "Source directory: $WIN32_DIR"
echo "Target directory: $AGENT_DIR"
echo "Backup directory: $BACKUP_DIR"
echo "================================================"

# Main executable files (based on NSI file analysis)
echo "Replacing main executable files..."

# Main monitoring agent executable
backup_and_replace \
    "$WIN32_DIR/monitoring-agent.exe" \
    "$AGENT_DIR/monitoring-agent.exe" \
    "monitoring-agent.exe.backup"

# Event channel version (if exists)
if [[ -f "$WIN32_DIR/monitoring-agent-eventchannel.exe" ]]; then
    backup_and_replace \
        "$WIN32_DIR/monitoring-agent-eventchannel.exe" \
        "$AGENT_DIR/monitoring-agent-eventchannel.exe" \
        "monitoring-agent-eventchannel.exe.backup"
fi

# Agent authentication executable
backup_and_replace \
    "$WIN32_DIR/agent-auth.exe" \
    "$AGENT_DIR/agent-auth.exe" \
    "agent-auth.exe.backup"

# Manage agents executable
backup_and_replace \
    "$WIN32_DIR/manage_agents.exe" \
    "$AGENT_DIR/manage_agents.exe" \
    "manage_agents.exe.backup"

# Win32 UI executable (renamed from os_win32ui.exe)
backup_and_replace \
    "$WIN32_DIR/os_win32ui.exe" \
    "$AGENT_DIR/win32ui.exe" \
    "win32ui.exe.backup"

# Configuration files
echo "Replacing configuration files..."

# Internal options configuration
backup_and_replace \
    "$WIN32_DIR/internal_options.conf" \
    "$AGENT_DIR/internal_options.conf" \
    "internal_options.conf.backup"

# Local internal options configuration
backup_and_replace \
    "$WIN32_DIR/default-local_internal_options.conf" \
    "$AGENT_DIR/local_internal_options.conf" \
    "local_internal_options.conf.backup"

# OSSEC configuration (only if default exists and target doesn't exist or user wants to replace)
if [[ -f "$WIN32_DIR/default-ossec.conf" ]]; then
    if [[ ! -f "$AGENT_DIR/ossec.conf" ]]; then
        echo "Creating initial ossec.conf from default..."
        cp "$WIN32_DIR/default-ossec.conf" "$AGENT_DIR/ossec.conf"
    else
        echo "ossec.conf already exists. Creating backup and offering replacement..."
        backup_and_replace \
            "$WIN32_DIR/default-ossec.conf" \
            "$AGENT_DIR/ossec.conf.new" \
            "ossec.conf.backup"
        echo "New ossec.conf saved as ossec.conf.new for manual review"
    fi
fi

# Alternatively, if user wants to force replace ossec.conf:
# backup_and_replace \
#     "$WIN32_DIR/default-ossec.conf" \
#     "$AGENT_DIR/ossec.conf" \
#     "ossec.conf.backup"

# DLL files
echo "Replacing DLL files..."

# Core DLL files
backup_and_replace \
    "$WIN32_DIR/libwinpthread-1.dll" \
    "$AGENT_DIR/libwinpthread-1.dll" \
    "libwinpthread-1.dll.backup"

backup_and_replace \
    "$WIN32_DIR/libgcc_s_dw2-1.dll" \
    "$AGENT_DIR/libgcc_s_dw2-1.dll" \
    "libgcc_s_dw2-1.dll.backup"

backup_and_replace \
    "$WIN32_DIR/libstdc++-6.dll" \
    "$AGENT_DIR/libstdc++-6.dll" \
    "libstdc++-6.dll.backup"

# Setup executables
echo "Replacing setup executables..."

# Setup utilities (copy to agent directory for convenience)
if [[ -f "$WIN32_DIR/setup-windows.exe" ]]; then
    backup_and_replace \
        "$WIN32_DIR/setup-windows.exe" \
        "$AGENT_DIR/setup-windows.exe" \
        "setup-windows.exe.backup"
fi

if [[ -f "$WIN32_DIR/setup-syscheck.exe" ]]; then
    backup_and_replace \
        "$WIN32_DIR/setup-syscheck.exe" \
        "$AGENT_DIR/setup-syscheck.exe" \
        "setup-syscheck.exe.backup"
fi

if [[ -f "$WIN32_DIR/setup-iis.exe" ]]; then
    backup_and_replace \
        "$WIN32_DIR/setup-iis.exe" \
        "$AGENT_DIR/setup-iis.exe" \
        "setup-iis.exe.backup"
fi

# Active response binaries
echo "Replacing active response binaries..."

# Create active-response/bin directory if it doesn't exist
mkdir -p "$AGENT_DIR/active-response/bin"

# Route null executable
backup_and_replace \
    "$WIN32_DIR/route-null.exe" \
    "$AGENT_DIR/active-response/bin/route-null.exe" \
    "route-null.exe.backup"

# Restart monitoring executable (renamed from restart-wazuh.exe)
backup_and_replace \
    "$WIN32_DIR/restart-wazuh.exe" \
    "$AGENT_DIR/active-response/bin/restart-monitoring.exe" \
    "restart-monitoring.exe.backup"

# Netsh executable
backup_and_replace \
    "$WIN32_DIR/netsh.exe" \
    "$AGENT_DIR/active-response/bin/netsh.exe" \
    "netsh.exe.backup"

# Security and certificate files
echo "Replacing security files..."

# WPK root certificate (from etc directory as specified in NSI)
if [[ -f "/home/anandhu/Desktop/monitoring_agent/etc/wpk_root.pem" ]]; then
    backup_and_replace \
        "/home/anandhu/Desktop/monitoring_agent/etc/wpk_root.pem" \
        "$AGENT_DIR/wpk_root.pem" \
        "wpk_root.pem.backup"
fi

# Version file
echo "Replacing version file..."
backup_and_replace \
    "$WIN32_DIR/VERSION.json" \
    "$AGENT_DIR/VERSION.json" \
    "VERSION.json.backup"

# Documentation and help files
echo "Replacing documentation files..."

# Help file
backup_and_replace \
    "$WIN32_DIR/help_win.txt" \
    "$AGENT_DIR/help.txt" \
    "help.txt.backup"

# Vista security file
backup_and_replace \
    "$WIN32_DIR/vista_sec.txt" \
    "$AGENT_DIR/vista_sec.txt" \
    "vista_sec.txt.backup"

# Additional DLL files from build directories (if they exist)
echo "Checking for additional DLL files..."

# Wazuh extension DLL
if [[ -f "/home/anandhu/Desktop/monitoring_agent/src/libwazuhext.dll" ]]; then
    backup_and_replace \
        "/home/anandhu/Desktop/monitoring_agent/src/libwazuhext.dll" \
        "$AGENT_DIR/libwazuhext.dll" \
        "libwazuhext.dll.backup"
fi

# Wazuh shared DLL
if [[ -f "/home/anandhu/Desktop/monitoring_agent/src/libwazuhshared.dll" ]]; then
    backup_and_replace \
        "/home/anandhu/Desktop/monitoring_agent/src/libwazuhshared.dll" \
        "$AGENT_DIR/libwazuhshared.dll" \
        "libwazuhshared.dll.backup"
fi

# Database sync DLL
if [[ -f "/home/anandhu/Desktop/monitoring_agent/src/shared_modules/dbsync/build/bin/dbsync.dll" ]]; then
    backup_and_replace \
        "/home/anandhu/Desktop/monitoring_agent/src/shared_modules/dbsync/build/bin/dbsync.dll" \
        "$AGENT_DIR/dbsync.dll" \
        "dbsync.dll.backup"
fi

# Rsync DLL
if [[ -f "/home/anandhu/Desktop/monitoring_agent/src/shared_modules/rsync/build/bin/rsync.dll" ]]; then
    backup_and_replace \
        "/home/anandhu/Desktop/monitoring_agent/src/shared_modules/rsync/build/bin/rsync.dll" \
        "$AGENT_DIR/rsync.dll" \
        "rsync.dll.backup"
fi

# System info DLL
if [[ -f "/home/anandhu/Desktop/monitoring_agent/src/data_provider/build/bin/sysinfo.dll" ]]; then
    backup_and_replace \
        "/home/anandhu/Desktop/monitoring_agent/src/data_provider/build/bin/sysinfo.dll" \
        "$AGENT_DIR/sysinfo.dll" \
        "sysinfo.dll.backup"
fi

# System collector DLL
if [[ -f "/home/anandhu/Desktop/monitoring_agent/src/wazuh_modules/syscollector/build/bin/syscollector.dll" ]]; then
    backup_and_replace \
        "/home/anandhu/Desktop/monitoring_agent/src/wazuh_modules/syscollector/build/bin/syscollector.dll" \
        "$AGENT_DIR/syscollector.dll" \
        "syscollector.dll.backup"
fi

# FIM database DLL
if [[ -f "/home/anandhu/Desktop/monitoring_agent/src/syscheckd/build/bin/libfimdb.dll" ]]; then
    backup_and_replace \
        "/home/anandhu/Desktop/monitoring_agent/src/syscheckd/build/bin/libfimdb.dll" \
        "$AGENT_DIR/libfimdb.dll" \
        "libfimdb.dll.backup"
fi

# Syscollector configuration
if [[ -f "/home/anandhu/Desktop/monitoring_agent/src/wazuh_modules/syscollector/norm_config.json" ]]; then
    mkdir -p "$AGENT_DIR/queue/syscollector"
    backup_and_replace \
        "/home/anandhu/Desktop/monitoring_agent/src/wazuh_modules/syscollector/norm_config.json" \
        "$AGENT_DIR/queue/syscollector/norm_config.json" \
        "norm_config.json.backup"
fi

echo "================================================"
echo "BACKUP AND REPLACEMENT COMPLETED SUCCESSFULLY!"
echo "================================================"
echo "Backup location: $BACKUP_DIR"
echo ""
echo "Summary of replaced files:"
echo "- Main executables: monitoring-agent.exe, agent-auth.exe, manage_agents.exe, win32ui.exe"
echo "- Configuration files: internal_options.conf, local_internal_options.conf"
echo "- DLL files: libwinpthread-1.dll, libgcc_s_dw2-1.dll, libstdc++-6.dll"
echo "- Active response binaries: route-null.exe, restart-monitoring.exe, netsh.exe"
echo "- Security files: wpk_root.pem"
echo "- Documentation: help.txt, vista_sec.txt"
echo "- Version file: VERSION.json"
echo "- Additional DLLs (if found): libwazuhext.dll, libwazuhshared.dll, dbsync.dll, etc."
echo ""
echo "IMPORTANT NOTES:"
echo "1. All original files have been backed up to: $BACKUP_DIR"
echo "2. ossec.conf was handled specially - check for .new file if it exists"
echo "3. Review the backup directory if you need to restore any files"
echo "4. Test the monitoring agent functionality after replacement"
echo "================================================"

# Create a restore script
echo "Creating restore script..."
cat > "$BACKUP_DIR/restore_from_backup.sh" << 'RESTORE_EOF'
#!/bin/bash

# Restore script to rollback file replacements
# This script restores files from the backup directory

BACKUP_DIR="$(dirname "$0")"
AGENT_DIR="/home/anandhu/Desktop/monitoring_agent/src/win32/agent"

echo "Restoring files from backup: $BACKUP_DIR"
echo "Target directory: $AGENT_DIR"

# Restore function
restore_file() {
    local backup_file="$1"
    local dest_file="$2"
    
    if [[ -f "$BACKUP_DIR/$backup_file" ]]; then
        echo "Restoring: $backup_file -> $dest_file"
        cp "$BACKUP_DIR/$backup_file" "$dest_file"
    else
        echo "Backup file not found: $backup_file"
    fi
}

# Restore all backed up files
restore_file "monitoring-agent.exe.backup" "$AGENT_DIR/monitoring-agent.exe"
restore_file "agent-auth.exe.backup" "$AGENT_DIR/agent-auth.exe"
restore_file "manage_agents.exe.backup" "$AGENT_DIR/manage_agents.exe"
restore_file "win32ui.exe.backup" "$AGENT_DIR/win32ui.exe"
restore_file "internal_options.conf.backup" "$AGENT_DIR/internal_options.conf"
restore_file "local_internal_options.conf.backup" "$AGENT_DIR/local_internal_options.conf"
restore_file "libwinpthread-1.dll.backup" "$AGENT_DIR/libwinpthread-1.dll"
restore_file "libgcc_s_dw2-1.dll.backup" "$AGENT_DIR/libgcc_s_dw2-1.dll"
restore_file "libstdc++-6.dll.backup" "$AGENT_DIR/libstdc++-6.dll"
restore_file "route-null.exe.backup" "$AGENT_DIR/active-response/bin/route-null.exe"
restore_file "restart-monitoring.exe.backup" "$AGENT_DIR/active-response/bin/restart-monitoring.exe"
restore_file "netsh.exe.backup" "$AGENT_DIR/active-response/bin/netsh.exe"
restore_file "wpk_root.pem.backup" "$AGENT_DIR/wpk_root.pem"
restore_file "VERSION.json.backup" "$AGENT_DIR/VERSION.json"
restore_file "help.txt.backup" "$AGENT_DIR/help.txt"
restore_file "vista_sec.txt.backup" "$AGENT_DIR/vista_sec.txt"

# Add other files as needed
restore_file "libwazuhext.dll.backup" "$AGENT_DIR/libwazuhext.dll"
restore_file "libwazuhshared.dll.backup" "$AGENT_DIR/libwazuhshared.dll"
restore_file "dbsync.dll.backup" "$AGENT_DIR/dbsync.dll"
restore_file "rsync.dll.backup" "$AGENT_DIR/rsync.dll"
restore_file "sysinfo.dll.backup" "$AGENT_DIR/sysinfo.dll"
restore_file "syscollector.dll.backup" "$AGENT_DIR/syscollector.dll"
restore_file "libfimdb.dll.backup" "$AGENT_DIR/libfimdb.dll"
restore_file "norm_config.json.backup" "$AGENT_DIR/queue/syscollector/norm_config.json"

echo "Restore completed!"
RESTORE_EOF

chmod +x "$BACKUP_DIR/restore_from_backup.sh"
echo "Restore script created: $BACKUP_DIR/restore_from_backup.sh"

echo ""
echo "Script completed successfully!"