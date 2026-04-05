# Suricata Manager UI

A simple Windows GUI application to manage the Suricata IDS/IPS service.

## Features

- Start/Stop Suricata service
- View service status in real-time
- View Suricata logs
- Requires administrator privileges (automatically prompts)
- Clean, simple interface

## Files Created

- `suricata_ui.h` - Header file with definitions
- `suricata_ui.c` - Main implementation
- `suricata_ui.rc` - Resource file (dialogs, icons, version info)
- `suricata_ui.exe.manifest` - Manifest file for admin privileges
- `Makefile.suricata` - Build configuration

## Building

### Prerequisites
- MinGW-w64 or similar Windows development environment
- gcc compiler
- windres (Windows Resource Compiler)

### Build Commands

```bash
# Navigate to the UI directory
cd /home/anandhu/Desktop/monitoring_agent/src/win32/ui/

# Build using make
make -f Makefile.suricata

# Or build manually
windres suricata_ui.rc -O coff -o suricata_ui.res
gcc -Wall -O2 -DWIN32 -mwindows suricata_ui.c suricata_ui.res -o suricata_ui.exe -lcomctl32 -ladvapi32 -lshell32
```

## Integration with Installer

The installer has been updated to:

1. **Include the executable**: Copy `suricata_ui.exe` to `$INSTDIR`
2. **Create Start Menu shortcut**: "Suricata Manager" in the Monitoring Agent folder
3. **Check for running process**: Before uninstallation, verify UI is closed
4. **Remove on uninstall**: Clean up executable and shortcuts

## Usage

### Running the UI

The UI can be launched:
- From Start Menu: "Monitoring Agent" → "Suricata Manager"
- Directly: Double-click `suricata_ui.exe` in the installation directory
- It will automatically request administrator privileges

### UI Functions

**Manage Menu:**
- Start Suricata: Starts the Suricata Windows service
- Stop Suricata: Stops the Suricata Windows service
- Refresh Status: Updates the current service status
- Exit: Close the application

**View Menu:**
- View Logs: Opens the Suricata log file in Notepad

**Help Menu:**
- About: Shows version and copyright information

## Requirements

### Service Configuration

Before the UI can manage Suricata, the Suricata service must be installed on the system. The service name should be `Suricata`.

To install Suricata as a Windows service, you would typically use:

```powershell
# Example service installation (needs to be done separately)
sc create Suricata binPath= "C:\Program Files\monitoring-agent\suricata\bin\suricata.exe -c C:\Program Files\monitoring-agent\suricata\etc\suricata.yaml" start= demand
```

Or use the PowerShell script provided: `SuricataControl.ps1`

### Administrator Privileges

The application manifest requests administrator privileges (`requireAdministrator`). When a user launches the UI:
- Windows will show a UAC prompt
- User must accept to continue
- Without admin rights, the start/stop functions will be disabled

## Icon File

You need to provide a `suricata.ico` file in the same directory. This icon will be used for:
- Application window icon
- Start Menu shortcut
- Taskbar icon

See `SURICATA_ICON_README.md` for icon requirements.

## Troubleshooting

### UI won't start
- Ensure all DLL dependencies are present (should be included with Windows)
- Check that the manifest is properly embedded
- Run from administrator command prompt for testing

### Can't start/stop service
- Verify administrator privileges (check the UI title bar for shield icon)
- Ensure Suricata service is installed: `sc query Suricata`
- Check Windows Event Viewer for service errors

### Status shows "Unknown"
- Service may not be installed
- Service name may be different than expected ("Suricata")
- Insufficient permissions to query service status

## Development Notes

### Code Structure

- **IsUserAdmin()**: Checks if user has administrator rights
- **suricata_get_status()**: Queries Windows Service Control Manager for service status
- **suricata_start()**: Sends start command to service
- **suricata_stop()**: Sends stop command to service
- **update_status()**: Refreshes UI with current status
- **DlgProc()**: Main window message handler
- **WinMain()**: Application entry point

### Error Handling

All service operations return:
- `0` on success
- `-1` on error

The UI displays appropriate message boxes for user feedback.

## License

Copyright (C) 2026, Monitoring Solutions Inc.

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License (version 2) as
published by the FSF - Free Software Foundation.
