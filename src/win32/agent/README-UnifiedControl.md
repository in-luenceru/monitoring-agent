# Unified Security Agents Control System

This document explains the new unified control system for managing both RiskNoX Security Agent and Monitoring Agent.

## Overview

The unified system consists of several components that work together to provide seamless control and automatic startup of both security agents:

### Main Components

1. **UnifiedAgentControl.ps1** - Single wrapper file to control both agents
2. **UnifiedAutoStart.ps1** - Enhanced auto-startup script for both agents  
3. **Updated MonitoringAgentControl.ps1** - Enhanced with unified functionality
4. **RiskNoX-Agent-Installer.ps1** - Original RiskNoX agent control (unchanged)

## Features

### ✅ Single Control Interface
- One script to start, stop, restart, and check status of both agents
- Interactive menu system for easy management
- Command-line interface for automation

### ✅ Unified Auto-Startup
- Both agents start automatically after system reboot
- Intelligent startup detection (boot vs. user logon)
- Retry logic with exponential backoff
- Health monitoring and automatic recovery

### ✅ Comprehensive Monitoring
- Watchdog service monitors all processes
- Automatic restart of failed services
- Cooldown periods to prevent restart loops
- Detailed logging and Windows Event Log integration

### ✅ Subprocess Monitoring
- Monitors RiskNoX backend server and agent polling service
- Monitors Monitoring Agent main process
- Monitors Suricata Network IDS (if available)
- API connectivity testing for RiskNoX

## Quick Start

### 1. Using the Unified Control Interface

#### Interactive Menu
```powershell
.\UnifiedAgentControl.ps1
# or
.\UnifiedAgentControl.ps1 -Action menu
```

#### Command Line Usage
```powershell
# Start all agents
.\UnifiedAgentControl.ps1 -Action start

# Stop all agents
.\UnifiedAgentControl.ps1 -Action stop

# Restart all agents
.\UnifiedAgentControl.ps1 -Action restart

# Check status of all agents
.\UnifiedAgentControl.ps1 -Action status

# Start only RiskNoX agent
.\UnifiedAgentControl.ps1 -Action start-risknox

# Start only Monitoring agent
.\UnifiedAgentControl.ps1 -Action start-monitoring

# Configure auto-startup
.\UnifiedAgentControl.ps1 -Action configure-autostartup
```

#### Agent-Specific Control
```powershell
# Control specific agent only
.\UnifiedAgentControl.ps1 -Action start -Agent risknox
.\UnifiedAgentControl.ps1 -Action start -Agent monitoring
.\UnifiedAgentControl.ps1 -Action status -Agent both
```

### 2. Setting Up Auto-Startup

#### Method 1: Using Unified Control (Recommended)
```powershell
.\UnifiedAgentControl.ps1 -Action configure-autostartup
```

#### Method 2: Using Monitoring Agent Control
```powershell
.\MonitoringAgentControl.ps1 configure-autostartup
```

#### Manual Verification
```powershell
# Check if auto-startup is configured
Get-ScheduledTask -TaskName "MonitoringAgentAutoStart" -ErrorAction SilentlyContinue

# Test auto-startup manually
.\UnifiedAutoStart.ps1 -Mode test
```

### 3. Monitoring and Logs

#### View Unified Logs
```powershell
# Unified control logs
Get-Content logs\unified-control.log -Tail 20 -Wait

# Auto-startup logs
Get-Content logs\unified-auto-startup.log -Tail 20 -Wait

# Individual agent logs
Get-Content logs\backend.log -Tail 20        # RiskNoX backend
Get-Content logs\agent.log -Tail 20          # RiskNoX agent
Get-Content logs\agent-control.log -Tail 20  # Monitoring agent
```

#### Check Service Status
```powershell
# Comprehensive status check
.\UnifiedAgentControl.ps1 -Action status

# Test watchdog functionality
.\UnifiedAutoStart.ps1 -Mode test
```

## Architecture

### Service Components

#### RiskNoX Security Agent
- **Backend Server**: Python Flask server (localhost:5000)
- **Agent Service**: Polling service that communicates with backend
- **API Endpoint**: REST API for status and control

#### Monitoring Agent
- **Main Process**: monitoring-agent.exe
- **Suricata IDS**: Network intrusion detection (optional)
- **Configuration**: ossec.conf and client.keys

### Auto-Startup Flow

1. **System Boot Detection**: Determines if startup is due to boot or user logon
2. **System Readiness Check**: Waits for network and essential services
3. **Sequential Startup**: Starts RiskNoX first, then Monitoring Agent
4. **Health Verification**: Confirms all services are running and responsive
5. **Watchdog Activation**: Begins continuous monitoring

### Watchdog Features

- **Health Checks**: Every 30 seconds
- **Restart Logic**: Automatic recovery with cooldown periods
- **Failure Tracking**: Prevents restart loops
- **Event Logging**: Windows Event Log integration

## Configuration

### Watchdog Configuration
Edit `UnifiedAutoStart.ps1` to modify:
```powershell
$Script:WatchdogConfig = @{
    CheckInterval = 30          # Check every 30 seconds
    StartupRetries = 5          # Maximum startup retry attempts
    RetryDelay = 60             # Delay between retries (seconds)
    RestartCooldown = 120       # Minimum time between restarts (seconds)
    MaxRestartAttempts = 3      # Maximum restart attempts per hour
}
```

### Startup Delays
```powershell
$Script:StartupDelays = @{
    SystemBoot = 45             # Delay after system boot
    UserLogon = 15              # Delay after user logon
    ServiceRecovery = 30        # Delay for service recovery
    WakeFromSleep = 20          # Delay after wake from sleep
}
```

## Troubleshooting

### Common Issues

#### 1. Auto-Startup Not Working
```powershell
# Check scheduled task
Get-ScheduledTask -TaskName "MonitoringAgentAutoStart"

# Check task history
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-TaskScheduler/Operational'; ID=102} -MaxEvents 10

# Manually test startup
.\UnifiedAutoStart.ps1 -Mode startup
```

#### 2. Services Not Starting
```powershell
# Check detailed status
.\UnifiedAgentControl.ps1 -Action status

# Check individual logs
Get-Content logs\unified-auto-startup.log -Tail 50

# Test individual components
.\RiskNoX-Agent-Installer.ps1 -Action status
.\MonitoringAgentControl.ps1 status
```

#### 3. Watchdog Issues
```powershell
# Check watchdog status
.\UnifiedAutoStart.ps1 -Mode test

# View watchdog logs
Get-Content logs\unified-auto-startup.log | Select-String "watchdog"

# Stop existing watchdog
Get-Process pwsh | Where-Object {$_.CommandLine -like "*UnifiedAutoStart*"} | Stop-Process
```

### Log Locations

- **Unified Control**: `logs\unified-control.log`
- **Auto-Startup**: `logs\unified-auto-startup.log`
- **RiskNoX Backend**: `logs\backend.log` and `logs\backend_error.log`
- **RiskNoX Agent**: `logs\agent.log` and `logs\agent_error.log`
- **Monitoring Agent**: `logs\agent-control.log`
- **Task Scheduler**: `logs\task-scheduler.log`

## Migration from Individual Scripts

### Before (Manual Control)
```powershell
# Had to manage each agent separately
.\RiskNoX-Agent-Installer.ps1 -Action start
.\MonitoringAgentControl.ps1 start

# Different auto-startup mechanisms
.\MonitoringAgentControl.ps1 configure-autostartup
# (RiskNoX had no auto-startup)
```

### After (Unified Control)
```powershell
# Single command for everything
.\UnifiedAgentControl.ps1 -Action start

# Unified auto-startup for both
.\UnifiedAgentControl.ps1 -Action configure-autostartup
```

## API Integration

### Status Check Endpoints

The system provides several ways to check status programmatically:

#### PowerShell
```powershell
# Get status object
$status = & .\UnifiedAgentControl.ps1 -Action status
```

#### Command Line
```cmd
powershell -Command "& .\UnifiedAgentControl.ps1 -Action status"
```

#### HTTP (RiskNoX API)
```
GET http://localhost:5000/
```

## Support

For issues or questions:

1. Check the troubleshooting section above
2. Review log files in the `logs\` directory
3. Use test mode: `.\UnifiedAutoStart.ps1 -Mode test`
4. Verify individual agent functionality before using unified control

## Version History

- **v1.0.0**: Initial unified control system
- **v3.0.0**: Enhanced auto-startup with comprehensive monitoring
- Support for both RiskNoX Security Agent and Monitoring Agent
- Watchdog service with health monitoring
- Windows Event Log integration