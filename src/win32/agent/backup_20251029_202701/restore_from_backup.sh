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
