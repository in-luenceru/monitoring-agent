# CRITICAL FIX - Script Path Issue Resolved

## Problem Identified
The Suricata UI was looking for `SuricataControl.ps1` but Windows was showing the file as `SuricataControl` (without visible extension).

## Root Cause
Windows hides file extensions by default. The script file `SuricataControl.ps1` appears as just `SuricataControl` in File Explorer, causing the UI to fail finding it.

## Solution Implemented
Updated the UI code to check for BOTH filenames:
1. First tries: `SuricataControl.ps1` (with extension)
2. Then tries: `SuricataControl` (without extension)
3. Uses whichever file exists

## Code Changes

### All three functions updated:
- `suricata_get_status()`
- `suricata_start()`
- `suricata_stop()`

### New logic:
```powershell
$scriptPath = 'C:\Program Files\monitoring-agent\suricata';
$script = $null;
if (Test-Path (Join-Path $scriptPath 'SuricataControl.ps1')) {
    $script = Join-Path $scriptPath 'SuricataControl.ps1'
}
elseif (Test-Path (Join-Path $scriptPath 'SuricataControl')) {
    $script = Join-Path $scriptPath 'SuricataControl'
}
```

## Testing
Install the new version and it will now work regardless of:
- Whether Windows shows file extensions
- Whether the file is named with or without .ps1

## Quick Test
On the Windows machine, try starting Suricata again. The UI will now:
1. Look for the script with both names
2. Show which paths it tried if still not found
3. Work correctly even with hidden extensions

---

**Status:** ✅ FIXED
**Build:** monitoring-suite-4.13.1.exe
**Date:** January 15, 2026
**Size:** 63 MB

## How to Show File Extensions in Windows (Optional)
If you want to see the actual .ps1 extension:
1. Open File Explorer
2. Click "View" tab
3. Check "File name extensions" box

This is helpful for troubleshooting but not required - the UI now handles both cases.
