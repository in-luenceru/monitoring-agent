# RiskNoX Service Control - Complete Guide

## Overview

**RiskNoXServiceControl.ps1** is a unified control script that manages the entire RiskNoX Monitoring Agent Supervisor Service lifecycle. It provides a single interface for installation, configuration, operation, and maintenance.

## Features

✅ **One-Click Installation** - Installs all dependencies, builds the service, and configures everything automatically  
✅ **Automatic Restart** - Service and processes restart automatically on crash  
✅ **Persistent Operation** - Runs across system reboots  
✅ **Admin-Only Stop** - Only administrators can stop the service (security feature)  
✅ **Process Monitoring** - Monitors backend_server, monitoring_agent, and suricata_ids  
✅ **Detailed Status** - Real-time status of all managed processes  

---

## Quick Start Guide

### 1. Install Everything

```powershell
.\RiskNoXServiceControl.ps1 install
```

This single command will:
- ✅ Check prerequisites (Windows version, admin rights)
- ✅ Install Python 3.11.9 (if not present)
- ✅ Install all Python dependencies
- ✅ Build supervisor executable (supervisor.exe)
- ✅ Install Windows service
- ✅ Configure SYSTEM account permissions
- ✅ Set up automatic restart on failure

**Duration:** 2-5 minutes (depending on internet speed and system performance)

**Requirements:**
- Windows 10 or later
- Administrator privileges
- 2GB free disk space
- Internet connection (for Python download)

---

### 2. Configure Agent

```powershell
.\RiskNoXServiceControl.ps1 configure
```

This redirects to `UnifiedAgentControl.ps1 configure` for agent enrollment. You'll see the same terminal output as running UnifiedAgentControl.ps1 directly.

**What it does:**
- Enrolls the monitoring agent with the manager server
- Configures client keys
- Sets up agent authentication
- Configures manager IP address

---

### 3. Start Service

```powershell
.\RiskNoXServiceControl.ps1 start
```

**What it does:**
- Starts the Windows service
- Launches all three managed processes:
  - `backend_server` (Python web API on port 5000)
  - `monitoring_agent` (OSSEC-based security agent)
  - `suricata_ids` (Network intrusion detection)
- Verifies each process is running
- Shows real-time status

**Output Example:**
```
═══════════════════════════════════════════════════════════
  STARTING RiskNoX Monitoring Agent Service
═══════════════════════════════════════════════════════════

  ℹ Starting RiskNoX Monitoring Agent Supervisor...
  ✓ Service started successfully

  ℹ Waiting for managed processes to initialize...

  ℹ Verifying managed processes...

  ✓ backend_server: RUNNING
      PID: 12345
  ✓ monitoring_agent: RUNNING
      PID: 12346
  ✓ suricata_ids: RUNNING
      PID: 12347

  ✓ All managed processes are running

  ℹ Service is configured to:
    • Start automatically on system boot
    • Restart automatically if processes crash
    • Run until explicitly stopped by administrator
```

**Behavior:**
- Service starts automatically on system boot
- Processes remain running until service is explicitly stopped
- If any process crashes, supervisor automatically restarts it
- Service persists across system reboots

---

### 4. Check Status

```powershell
.\RiskNoXServiceControl.ps1 status
```

**Shows:**
- Windows service status (Running/Stopped)
- Port status (5000, 8765)
- Agent enrollment status
- All managed processes with:
  - Process state (RUNNING, STOPPED, FAILED, etc.)
  - Process ID (PID)
  - Uptime
  - Restart count
- Log file locations

**Output Example:**
```
═══════════════════════════════════════════════════════════
  RiskNoX Monitoring Agent Service Status
═══════════════════════════════════════════════════════════

  ℹ Service Status:
  Service:        RUNNING
  Start Type:     Automatic
  Display Name:   RiskNoX Monitoring Agent Supervisor

  ℹ Port Status:
  ✓ Backend API (5000):  LISTENING
  ✓ Control API (8765):  LISTENING

  ℹ Agent Enrollment:
  ✓ Client keys configured
    Manager IP: 127.0.0.1

  ℹ Managed Processes:

  ✓ backend_server:
      State:          RUNNING
      PID:            12345
      Uptime:         2h 15m
      Restart Count:  0

  ✓ monitoring_agent:
      State:          RUNNING
      PID:            12346
      Uptime:         2h 15m
      Restart Count:  0

  ✓ suricata_ids:
      State:          RUNNING
      PID:            12347
      Uptime:         2h 14m
      Restart Count:  0

  Summary:
    Total Processes:  3
    Running:          3

  ℹ Log Files:
    Supervisor:     logs\supervisor.log
    Backend:        logs\backend_server_stdout.log
    Agent:          logs\monitoring_agent_stdout.log
    Suricata:       logs\suricata_ids_stdout.log
```

---

## All Available Commands

### `install`
**Full installation of the service and all dependencies**

```powershell
.\RiskNoXServiceControl.ps1 install
```

- Checks prerequisites
- Installs Python (if needed)
- Installs Python packages
- Builds supervisor.exe
- Installs Windows service
- Configures permissions
- Sets up automatic restart

**Requires:** Administrator privileges  
**Duration:** 2-5 minutes

---

### `configure`
**Configure agent enrollment (redirects to UnifiedAgentControl.ps1)**

```powershell
.\RiskNoXServiceControl.ps1 configure
```

- Enrolls monitoring agent
- Configures client keys
- Sets manager IP
- Shows UnifiedAgentControl.ps1 output

**Requires:** Service must be installed first

---

### `start`
**Start the service and verify all processes**

```powershell
.\RiskNoXServiceControl.ps1 start
```

- Starts Windows service
- Waits for service to initialize
- Launches all managed processes
- Verifies each process is running
- Shows real-time status

**Behavior:**
- If already running, shows current status
- Waits up to 30 seconds for service to start
- Waits 10 seconds for processes to initialize
- Queries Control API for process status

---

### `stop`
**Stop the service and all managed processes**

```powershell
.\RiskNoXServiceControl.ps1 stop
```

- Stops Windows service
- Stops all managed processes
- Waits for clean shutdown

**Requires:** Administrator privileges  
**Security:** Only admins can stop the service

---

### `status`
**Show detailed status of service and all processes**

```powershell
.\RiskNoXServiceControl.ps1 status
```

- Service status
- Port status (5000, 8765)
- Enrollment status
- Process details (state, PID, uptime, restarts)
- Summary statistics
- Log file locations

**No privileges required** - Any user can check status

---

### `restart`
**Restart the service**

```powershell
.\RiskNoXServiceControl.ps1 restart
```

- Stops service
- Waits 5 seconds
- Starts service
- Verifies processes

**Requires:** Administrator privileges

---

### `uninstall`
**Completely remove the service**

```powershell
.\RiskNoXServiceControl.ps1 uninstall
```

- Stops service
- Removes Windows service
- Asks for confirmation
- Preserves application files

**Requires:** Administrator privileges  
**Note:** Application files are NOT deleted

---

### `help`
**Show help message**

```powershell
.\RiskNoXServiceControl.ps1 help
```

Shows command list, examples, and notes.

---

## Service Behavior

### Automatic Startup
- Service is configured with **StartType = Automatic**
- Starts automatically when Windows boots
- No manual intervention required after system restart

### Process Monitoring
- Supervisor monitors all 3 processes continuously
- Health checks every 15 seconds
- Automatic restart on crash or failure
- Configurable retry limits

### Crash Recovery
- If a process crashes, supervisor restarts it automatically
- Exponential backoff: 5s, 10s, 30s delays
- After 3 failures, process marked as failed
- Service failure actions: restart after 5s, 10s, 30s

### Admin-Only Stop
- Service is configured to require administrator privileges to stop
- Regular users cannot stop the service
- Prevents unauthorized service termination
- Security feature for production deployments

### Persistence
- Service runs continuously until explicitly stopped
- Survives system reboots
- Survives user logoff
- Runs as LocalSystem account

---

## Process Details

### 1. backend_server
- **Type:** Python web API
- **Port:** 5000
- **Purpose:** Web interface for monitoring and control
- **Health Check:** HTTP GET to `http://127.0.0.1:5000/api/health`
- **Logs:** 
  - `logs\backend_server_stdout.log`
  - `logs\backend_server_stderr.log`

### 2. monitoring_agent
- **Type:** OSSEC-based security agent
- **Purpose:** System monitoring and security event collection
- **Health Check:** Process existence + PID file check
- **Configuration:** `ossec.conf`, `client.keys`
- **Logs:**
  - `logs\monitoring_agent_stdout.log`
  - `logs\monitoring_agent_stderr.log`

### 3. suricata_ids
- **Type:** Network intrusion detection system
- **Purpose:** Network traffic analysis and threat detection
- **Health Check:** Process existence + PID file check
- **Configuration:** `suricata\suricata.yaml`
- **Logs:**
  - `logs\suricata_ids_stdout.log`
  - `logs\suricata_ids_stderr.log`
  - `suricata\log\suricata.log`

---

## Control API

### Endpoint
`http://127.0.0.1:8765/api/status`

### Authentication
Bearer token authentication using `config\supervisor_token.txt`

### Example Request
```powershell
$token = Get-Content "config\supervisor_token.txt" -Raw | ForEach-Object { $_.Trim() }
$headers = @{ "Authorization" = "Bearer $token" }
$response = Invoke-RestMethod -Uri "http://127.0.0.1:8765/api/status" -Headers $headers
```

### Response Format
```json
{
  "processes": [
    {
      "name": "backend_server",
      "state": "running",
      "pid": 12345,
      "restart_count": 0,
      "last_health_check": "2025-10-02T10:30:45.123456"
    },
    {
      "name": "monitoring_agent",
      "state": "running",
      "pid": 12346,
      "restart_count": 0,
      "last_health_check": "2025-10-02T10:30:45.234567"
    },
    {
      "name": "suricata_ids",
      "state": "running",
      "pid": 12347,
      "restart_count": 0,
      "last_health_check": "2025-10-02T10:30:45.345678"
    }
  ]
}
```

---

## Troubleshooting

### Service Won't Start

**Symptom:** `Start-Service` fails or service stops immediately

**Solutions:**
1. Check SYSTEM account has permissions:
   ```powershell
   icacls "C:\path\to\monitoring-agent-windows" /grant "SYSTEM:(OI)(CI)F" /T /Q
   ```

2. Check supervisor.log for errors:
   ```powershell
   Get-Content logs\supervisor.log -Tail 50
   ```

3. Verify config file exists:
   ```powershell
   Test-Path config\services.yml
   ```

4. Reinstall service:
   ```powershell
   .\RiskNoXServiceControl.ps1 uninstall
   .\RiskNoXServiceControl.ps1 install
   ```

---

### Process Not Running

**Symptom:** Status shows process as STOPPED or FAILED

**Solutions:**
1. Check process-specific logs:
   ```powershell
   Get-Content logs\backend_server_stderr.log -Tail 50
   Get-Content logs\monitoring_agent_stderr.log -Tail 50
   Get-Content logs\suricata_ids_stderr.log -Tail 50
   ```

2. Check if agent is enrolled (for monitoring_agent):
   ```powershell
   Test-Path client.keys
   Get-Content client.keys
   ```

3. Check Suricata configuration:
   ```powershell
   Test-Path suricata\suricata.yaml
   ```

4. Restart service:
   ```powershell
   .\RiskNoXServiceControl.ps1 restart
   ```

---

### Control API Not Responding

**Symptom:** Status command shows "Could not query Control API"

**Solutions:**
1. Verify token file exists:
   ```powershell
   Test-Path config\supervisor_token.txt
   ```

2. Check port 8765 is listening:
   ```powershell
   Test-NetConnection -ComputerName 127.0.0.1 -Port 8765
   ```

3. Wait 10-15 seconds after starting service (initialization time)

4. Check supervisor.log:
   ```powershell
   Get-Content logs\supervisor.log | Select-String "Control API"
   ```

---

### "Access Denied" When Stopping Service

**Symptom:** Stop command fails with access denied error

**Solution:**
Run PowerShell as Administrator:
```powershell
Start-Process powershell -Verb RunAs -ArgumentList '-File "RiskNoXServiceControl.ps1" stop'
```

This is by design - only admins can stop the service.

---

## Deployment to Other Devices

### Prerequisites
- Windows 10 or Windows 11
- Administrator privileges
- Internet connection (for Python installation)
- 2GB free disk space

### Step-by-Step Deployment

1. **Copy files to target device**
   ```powershell
   # Copy entire monitoring-agent-windows folder
   Copy-Item -Path "monitoring-agent-windows" -Destination "C:\Path\On\Target" -Recurse
   ```

2. **Open PowerShell as Administrator**
   ```powershell
   Start-Process powershell -Verb RunAs
   ```

3. **Navigate to directory**
   ```powershell
   cd "C:\Path\On\Target\monitoring-agent-windows"
   ```

4. **Install**
   ```powershell
   .\RiskNoXServiceControl.ps1 install
   ```

5. **Configure**
   ```powershell
   .\RiskNoXServiceControl.ps1 configure
   ```

6. **Start**
   ```powershell
   .\RiskNoXServiceControl.ps1 start
   ```

7. **Verify**
   ```powershell
   .\RiskNoXServiceControl.ps1 status
   ```

**That's it!** The service is now running and will:
- ✅ Start automatically on system boot
- ✅ Restart automatically on crash
- ✅ Run continuously until stopped by admin
- ✅ Monitor all processes 24/7

---

## Log Files

All logs are in the `logs\` directory:

| Log File | Purpose |
|----------|---------|
| `supervisor.log` | Main supervisor service log |
| `service-control.log` | RiskNoXServiceControl.ps1 operations |
| `backend_server_stdout.log` | Backend API standard output |
| `backend_server_stderr.log` | Backend API errors |
| `agent_poll_stdout.log` | Agent poller output |
| `agent_poll_stderr.log` | Agent poller errors |
| `monitoring_agent_stdout.log` | Monitoring agent output |
| `monitoring_agent_stderr.log` | Monitoring agent errors |
| `suricata_ids_stdout.log` | Suricata IDS output |
| `suricata_ids_stderr.log` | Suricata IDS errors |

### Viewing Logs

**Tail last 50 lines:**
```powershell
Get-Content logs\supervisor.log -Tail 50
```

**Follow in real-time:**
```powershell
Get-Content logs\supervisor.log -Wait
```

**Search for errors:**
```powershell
Get-Content logs\supervisor.log | Select-String "ERROR"
```

**View logs from specific time:**
```powershell
Get-Content logs\supervisor.log | Select-String "2025-10-02 10:"
```

---

## Configuration Files

| File | Purpose |
|------|---------|
| `config\services.yml` | Supervisor process definitions |
| `config\agent_config.json` | Agent configuration |
| `config\blocked_apps.json` | Application blocking rules |
| `config\blocked_urls.json` | URL blocking rules |
| `config\settings.json` | Backend server settings |
| `config\supervisor_token.txt` | Control API authentication token |
| `ossec.conf` | Monitoring agent configuration |
| `client.keys` | Agent enrollment keys |
| `suricata\suricata.yaml` | Suricata IDS configuration |

---

## Security Features

### 1. Admin-Only Stop
- Service stop requires administrator privileges
- Prevents unauthorized service termination
- Configured via Windows service security descriptor

### 2. Control API Authentication
- Bearer token authentication
- Token stored in `config\supervisor_token.txt`
- Auto-generated on first run
- 64-character hexadecimal token

### 3. LocalSystem Account
- Service runs as LocalSystem
- Full system privileges for monitoring
- Isolated from user sessions
- SYSTEM account has explicit folder permissions

### 4. Automatic Restart
- Service restarts automatically on failure
- Prevents denial of service
- Configurable failure actions
- Exponential backoff on repeated failures

---

## Performance

### Resource Usage (Typical)

| Process | CPU | Memory | Disk I/O |
|---------|-----|--------|----------|
| supervisor.exe | <1% | ~50MB | Low |
| backend_server | <1% | ~30MB | Low |
| monitoring_agent | <2% | ~20MB | Low |
| suricata_ids | 1-5% | ~100MB | Medium |
| **Total** | **<10%** | **~200MB** | **Low-Medium** |

### Network Usage
- Backend API: Minimal (local only)
- Monitoring Agent: Low (periodic reporting)
- Suricata IDS: Medium-High (network monitoring)

---

## FAQ

### Q: Can regular users stop the service?
**A:** No. Only administrators can stop the service. This is a security feature.

### Q: What happens if the system reboots?
**A:** The service starts automatically on boot. No manual intervention needed.

### Q: What happens if a process crashes?
**A:** The supervisor automatically restarts it within seconds.

### Q: Can I run this on Windows 11 Home?
**A:** Yes, Windows 10/11 Home, Pro, Enterprise, all work.

### Q: Does it require internet connection after installation?
**A:** No. Only needed during installation for Python download.

### Q: How do I update the agent configuration?
**A:** Run `.\RiskNoXServiceControl.ps1 configure` again.

### Q: Can I view logs from Windows Event Viewer?
**A:** No, logs are in `logs\` directory only. Use `Get-Content` to view.

### Q: How do I check which version is installed?
**A:** Check `VERSION.json` or `Get-Content VERSION.json | ConvertFrom-Json`

### Q: Can I change the ports?
**A:** Yes, edit `config\services.yml` and restart service.

### Q: Is there a GUI?
**A:** Yes, backend API provides web interface on port 5000.

---

## Support

### Documentation
- `README-AgentControl.md` - UnifiedAgentControl.ps1 guide
- `README-UnifiedControl.md` - Unified control documentation
- `IMPLEMENTATION-SUMMARY.md` - Implementation details
- `FEATURE_PARITY_ANALYSIS.md` - Feature comparison

### Logs
Check logs in `logs\` directory for detailed information.

### Version
Check `VERSION.json` for version information.

---

## License

RiskNoX Monitoring Agent - Proprietary Software

---

**Last Updated:** October 2, 2025  
**Version:** See VERSION.json
