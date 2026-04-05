# Fix: Service Control Backend - PowerShell 7 Compatibility

## Issue Resolved ✅

The service control backend was failing to stop/start the service due to PowerShell version incompatibility.

### Root Cause

The backend was using `powershell` (Windows PowerShell 5.1) but the system uses `pwsh` (PowerShell 7). The RiskNoXServiceControl.ps1 script has syntax that works in PowerShell 7 but fails to parse in Windows PowerShell 5.1.

### Symptoms

- Frontend showed "Failed to stop service" with parsing errors
- PowerShell script threw syntax errors about unexpected tokens
- Commands like `stop`, `start`, `restart` didn't work from the web interface

### Solution Applied

Updated `service_control_backend.py` to use `pwsh` (PowerShell 7) instead of `powershell` (Windows PowerShell 5.1) in all subprocess calls.

**Changes made:**
- ✅ Updated service status checks to use `pwsh`
- ✅ Updated process detection to use `pwsh`
- ✅ Updated start/stop/restart commands to use `pwsh`
- ✅ Updated admin privilege checks to use `pwsh`

### Testing Results

All operations now work correctly:

#### ✅ Status Check
```json
{
  "service_name": "RiskNoXSupervisor",
  "status": "Running",
  "start_type": "Automatic",
  "processes": {
    "backend_server": {"running": true, "pid": 3536},
    "monitoring_agent": {"running": true, "pid": 9152},
    "suricata": {"running": true, "pid": 14092}
  }
}
```

#### ✅ Stop Service
- Successfully stops service
- Temporarily removes protection
- Stops all managed processes
- Returns success message

#### ✅ Start Service  
- Successfully starts service
- Reapplies protection
- Starts all managed processes
- Verifies process status

### Additional Fixes Applied

1. **Process Detection Enhancement**
   - Backend server: Now correctly identifies python.exe running backend_server.py
   - Monitoring agent: Uses correct process name `monitoring-agent`
   - Suricata: Uses correct process name `suricata`

2. **Status Code Translation**
   - Converts numeric status codes to readable strings
   - Status: 4 → "Running", 1 → "Stopped"
   - StartType: 2 → "Automatic", 3 → "Manual"

### File Modified

**`service_control_backend.py`**
- Line ~30: Changed `["powershell", ...]` to `["pwsh", ...]`
- Line ~118: Changed `["powershell", ...]` to `["pwsh", ...]`
- Line ~144: Changed `["powershell", ...]` to `["pwsh", ...]`
- Line ~161: Changed `["powershell", ...]` to `["pwsh", ...]`
- Line ~208: Changed `["powershell", ...]` to `["pwsh", ...]`
- Line ~229: Changed `["powershell", ...]` to `["pwsh", ...]`
- Line ~251: Changed `["powershell", ...]` to `["pwsh", ...]`
- Line ~286: Changed `["powershell", ...]` to `["pwsh", ...]`
- Line ~307: Changed `["powershell", ...]` to `["pwsh", ...]`

### How to Verify

1. **Test Status:**
   ```powershell
   Invoke-RestMethod -Uri "http://localhost:5001/api/service/status" | ConvertTo-Json
   ```

2. **Test Stop (requires admin):**
   ```powershell
   Invoke-RestMethod -Uri "http://localhost:5001/api/service/stop" -Method Post | ConvertTo-Json
   ```

3. **Test Start:**
   ```powershell
   Invoke-RestMethod -Uri "http://localhost:5001/api/service/start" -Method Post | ConvertTo-Json
   ```

4. **Or use the web interface:**
   ```
   http://localhost:5001
   ```

### Requirements

- ✅ PowerShell 7 (pwsh) must be installed
- ✅ PowerShell 7 must be in system PATH
- ✅ Service control backend must be restarted after the fix

### Restart Backend

```powershell
# Stop old backend
Get-Process python | Where-Object { 
    (Get-CimInstance Win32_Process -Filter "ProcessId = $($_.Id)").CommandLine -like "*service_control_backend.py*" 
} | Stop-Process -Force

# Start new backend
python service_control_backend.py
```

Or use the startup script:
```powershell
.\start_service_control.ps1
```

### Notes

- The service control script (RiskNoXServiceControl.ps1) is written for PowerShell 7
- Windows PowerShell 5.1 has different parsing rules for certain syntax
- PowerShell 7 is cross-platform and more modern
- No changes were needed to RiskNoXServiceControl.ps1 itself

### Browser Testing

Open `http://localhost:5001` and verify:

1. ✅ Service status displays correctly
2. ✅ All three processes show "Running" with PIDs
3. ✅ Start button works
4. ✅ Stop button works (with admin privileges)
5. ✅ Restart button works (with admin privileges)
6. ✅ Status auto-refreshes every 10 seconds

---

**Fixed:** October 3, 2025  
**Status:** ✅ Resolved  
**Impact:** High - Core functionality restored
