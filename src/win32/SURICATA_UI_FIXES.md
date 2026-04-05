# Suricata UI Fixes Applied - January 15, 2026

## Issues Fixed

### 1. **PowerShell Path Escaping**
- **Problem**: Backslashes in paths were not properly escaped for PowerShell
- **Fix**: Changed from `'%s\\suricata\\SuricataControl.ps1'` to using `Join-Path` cmdlet
- **New approach**: `$script = Join-Path '%s' 'suricata\SuricataControl.ps1'`

### 2. **PowerShell Executable**
- **Problem**: Code was using `pwsh.exe` (PowerShell 7+) which may not be installed
- **Fix**: Changed back to `powershell.exe` (Windows PowerShell 5.1, built-in on Windows)

### 3. **Timeout Too Short**
- **Problem**: 30 seconds wasn't enough for Suricata to start
- **Fix**: Increased timeout from 30,000ms to 60,000ms (60 seconds)

### 4. **No Error Details**
- **Problem**: Generic error message didn't show what actually failed
- **Fix**: Added detailed error capture and display:
  - Captures all PowerShell output (stdout + stderr)
  - Stores last error message in global variable
  - Displays full error details in message box
  - Shows helpful troubleshooting steps

### 5. **Error Handling Improvements**
- Added try-catch blocks in PowerShell commands
- Better output parsing to detect SUCCESS/FAILED states
- Error messages now include:
  - What went wrong
  - Expected file paths
  - Troubleshooting checklist

## Code Changes

### New Function Added
```c
const char* suricata_get_last_error()
```
Returns the last error message captured from PowerShell execution.

### Updated Functions

**execute_powershell():**
- Increased buffer size for command line (2048 → 4096 bytes)
- Increased timeout (30s → 60s)

**suricata_get_status():**
- Better PowerShell path construction
- Error handling with try-catch
- Increased command buffer size

**suricata_start():**
- Detailed error capture
- Better boolean comparison (`$result -eq $true`)
- Script path verification
- Full error message display

**suricata_stop():**
- Same improvements as start function

**UI Message Boxes:**
- Now show detailed error information
- Include troubleshooting steps
- Display expected file paths

## What Users Will See Now

### Before (Generic Error):
```
Failed to start suricata service.
Please check if the service is installed.
```

### After (Detailed Error):
```
Failed to start Suricata service.

Error Details:
[Actual PowerShell error message here]
SCRIPT_NOT_FOUND: C:\Program Files\monitoring-agent\suricata\SuricataControl.ps1
or
ERROR: Cannot find path 'C:\Program Files\monitoring-agent\suricata\bin\suricata.exe'
or
FAILED: Function returned false

Please check:
1. PowerShell script exists at:
   C:\Program Files\monitoring-agent\suricata\SuricataControl.ps1
2. Suricata binary is present
3. Network interfaces are available
4. Npcap is properly installed
```

## Testing Steps

1. **Install the new installer:**
   ```
   monitoring-suite-4.13.1.exe
   ```

2. **Open Suricata Manager:**
   - Start Menu → Monitoring Agent → Suricata Manager
   - Should open with admin elevation

3. **Try to start Suricata:**
   - Click "Manage" → "Start Suricata"
   - Wait up to 60 seconds
   - Should either:
     - Show success message
     - Show detailed error with exact problem

4. **Check error details:**
   - If it fails, error message will show:
     - Exact PowerShell error
     - Missing file path
     - What to check next

## Common Errors and Solutions

### Error: "SCRIPT_NOT_FOUND"
**Cause:** PowerShell script is missing
**Solution:** 
- Verify file exists: `C:\Program Files\monitoring-agent\suricata\SuricataControl.ps1`
- Reinstall the application

### Error: "Cannot find path ...\\suricata.exe"
**Cause:** Suricata binary is missing
**Solution:**
- Verify file exists: `C:\Program Files\monitoring-agent\suricata\bin\suricata.exe`
- Check if Suricata files were installed correctly

### Error: "No active network interfaces found"
**Cause:** No network adapters detected or all disabled
**Solution:**
- Check Network and Sharing Center
- Enable at least one network adapter
- Verify adapter status in Device Manager

### Error: "Required npcap file missing"
**Cause:** Npcap DLLs not found
**Solution:**
- Verify files exist in: `C:\Program Files\monitoring-agent\npcap\`
- Required files: wpcap.dll, Packet.dll, NpcapHelper.exe
- Reinstall the application

### Error: "FAILED: Function returned false"
**Cause:** Suricata process failed to start
**Solution:**
- Check Suricata logs: `C:\Program Files\monitoring-agent\suricata\log\suricata.log`
- Verify configuration: `C:\Program Files\monitoring-agent\suricata\etc\suricata.yaml`
- Check Windows Event Viewer for additional errors

## Files Modified

- `src/win32/ui/suricata_ui.h` - Added error function declaration
- `src/win32/ui/suricata_ui.c` - Complete error handling rewrite
- `src/win32/suricata_ui.exe` - Rebuilt with fixes
- `src/win32/monitoring-suite-4.13.1.exe` - Updated installer

## Build Info

- **Build Date:** January 15, 2026
- **Compiler:** x86_64-w64-mingw32-gcc
- **UI Size:** 259 KB
- **Installer Size:** 63 MB
- **Status:** Successfully compiled with no warnings

## Next Steps

1. Test on Windows 10/11
2. Verify error messages are helpful
3. Confirm Suricata actually starts when conditions are correct
4. Check that detailed errors help diagnose issues

---

**Status:** ✅ FIXED AND REBUILT
**Ready for Testing:** YES
**Location:** `/home/anandhu/Desktop/monitoring_agent/src/win32/monitoring-suite-4.13.1.exe`
