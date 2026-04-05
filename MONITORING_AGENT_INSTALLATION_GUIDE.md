# Monitoring Agent MSI Installation Guide

## Overview
This guide explains how to build, install, and verify the fully-featured Monitoring Agent MSI package for Windows systems.

## Build Requirements

### Software Prerequisites
1. **WiX Toolset 3.11 or later**
   - Download from: https://wixtoolset.org/
   - Ensure `candle.exe` and `light.exe` are in PATH

2. **Windows SDK**
   - Required for signing tools (optional)

3. **MinGW Cross-Compiler** (for building from source)
   - `i686-w64-mingw32-gcc`

### Build Files Required
- `monitoring-agent.exe` (main executable)
- `monitoring-agent-eventchannel.exe` (event channel support)
- `manage_agents.exe` (agent management tool)
- `agent-auth.exe` (authentication tool)
- `default-ossec.conf` (default configuration)
- All manifest and resource files

## Building the MSI Package

### Method 1: Using Batch Script
```batch
cd src\win32
.\monitoring-installer-build-msi.bat 4.13.1 1
```

### Method 2: Using PowerShell Script (Recommended)
```powershell
cd src\win32
.\Build-MonitoringMSI.ps1 -Version 4.13.1 -Revision 1
```

### Method 3: Manual WiX Commands
```batch
candle.exe -nologo monitoring-installer.wxs -out monitoring-installer.wixobj -ext WixUtilExtension -ext WixUiExtension
light.exe monitoring-installer.wixobj -out monitoring-agent-4.13.1-1.msi -ext WixUtilExtension -ext WixUiExtension -spdb
```

## Installation Options

### Silent Installation (Recommended for Deployment)
```batch
msiexec /i monitoring-agent-4.13.1-1.msi /quiet ^
  MONITORING_MANAGER="192.168.1.100" ^
  MONITORING_REGISTRATION_PASSWORD="MySecurePassword" ^
  MONITORING_AGENT_NAME="WIN-SERVER-01" ^
  MONITORING_AGENT_GROUP="windows-servers"
```

### Interactive Installation
```batch
msiexec /i monitoring-agent-4.13.1-1.msi
```

### Advanced Configuration Options
```batch
msiexec /i monitoring-agent-4.13.1-1.msi /quiet ^
  MONITORING_MANAGER="192.168.1.100" ^
  MONITORING_MANAGER_PORT="1514" ^
  MONITORING_PROTOCOL="tcp" ^
  MONITORING_REGISTRATION_SERVER="192.168.1.100" ^
  MONITORING_REGISTRATION_PORT="1515" ^
  MONITORING_REGISTRATION_PASSWORD="SecurePassword123" ^
  MONITORING_KEEP_ALIVE_INTERVAL="60" ^
  MONITORING_TIME_RECONNECT="60" ^
  MONITORING_AGENT_NAME="MyWindowsAgent" ^
  MONITORING_AGENT_GROUP="production"
```

## Features Included

### Core Monitoring Capabilities
- **File Integrity Monitoring (FIM)**
  - Real-time file and registry monitoring
  - Checksum verification
  - File permission tracking

- **Log Analysis**
  - Windows Event Log collection
  - IIS log monitoring
  - Application log analysis
  - Custom log file monitoring

- **Security Event Detection**
  - Login/logout monitoring
  - Failed authentication attempts
  - Privilege escalation detection
  - Malware activity detection

- **System Monitoring**
  - Process monitoring
  - Network connection tracking
  - CPU and memory usage
  - Disk space monitoring

- **Policy Compliance**
  - Security Configuration Assessment (SCA)
  - CIS benchmark compliance
  - Custom policy rules
  - Registry compliance checking

- **Active Response**
  - Automated threat response
  - Custom response scripts
  - Firewall integration
  - Process termination

### Windows-Specific Features
- **Windows Event Channel Support**
  - Modern Windows event collection
  - Enhanced event filtering
  - Performance optimization

- **Registry Monitoring**
  - Real-time registry changes
  - Security-critical key monitoring
  - Configuration drift detection

- **Service Monitoring**
  - Service state tracking
  - Startup type monitoring
  - Service account auditing

## Service Management

### Service Information
- **Service Name**: MonitoringSvc
- **Display Name**: Monitoring Agent
- **Description**: Monitoring Windows Agent

### Service Commands
```batch
# Start the service
sc start MonitoringSvc

# Stop the service
sc stop MonitoringSvc

# Query service status
sc query MonitoringSvc

# View service configuration
sc qc MonitoringSvc
```

## Verification Steps

### 1. Installation Verification
```batch
# Check if service is installed
sc query MonitoringSvc

# Verify installation directory
dir "C:\Program Files (x86)\Monitoring Solutions Inc\Monitoring Agent"

# Check process in Task Manager
tasklist | findstr monitoring-agent.exe
```

### 2. Configuration Verification
```batch
# Check main configuration file
type "C:\Program Files (x86)\Monitoring Solutions Inc\Monitoring Agent\ossec.conf"

# Verify agent registration
type "C:\Program Files (x86)\Monitoring Solutions Inc\Monitoring Agent\client.keys"
```

### 3. Log Verification
```batch
# Check agent logs
type "C:\Program Files (x86)\Monitoring Solutions Inc\Monitoring Agent\logs\ossec.log"

# Monitor real-time logs
tail -f "C:\Program Files (x86)\Monitoring Solutions Inc\Monitoring Agent\logs\ossec.log"
```

## Troubleshooting

### Common Issues

#### Service Won't Start
1. Check Windows Event Logs
2. Verify configuration file syntax
3. Ensure proper permissions
4. Check firewall settings

#### Agent Not Connecting
1. Verify server IP and port
2. Check network connectivity
3. Validate authentication credentials
4. Review firewall rules

#### High CPU Usage
1. Adjust monitoring frequency
2. Optimize file monitoring rules
3. Review log collection settings
4. Check for configuration conflicts

### Log Locations
- **Agent Logs**: `C:\Program Files (x86)\Monitoring Solutions Inc\Monitoring Agent\logs\`
- **Windows Event Logs**: Event Viewer → Applications and Services Logs
- **Installation Logs**: `%TEMP%\MSI*.log`

### Configuration Files
- **Main Config**: `ossec.conf`
- **Agent Keys**: `client.keys`
- **Local Rules**: `local_rules.xml`
- **Local Decoders**: `local_decoder.xml`

## Uninstallation

### Method 1: Using MSI
```batch
msiexec /x monitoring-agent-4.13.1-1.msi /quiet
```

### Method 2: Using Product Code
```batch
msiexec /x {PRODUCT-GUID} /quiet
```

### Method 3: Control Panel
1. Open "Programs and Features"
2. Find "Monitoring Agent"
3. Click "Uninstall"

## Network Configuration

### Firewall Rules
```batch
# Allow outbound connections to manager
netsh advfirewall firewall add rule name="Monitoring Agent Outbound" dir=out action=allow protocol=TCP localport=1514

# Allow registration traffic
netsh advfirewall firewall add rule name="Monitoring Agent Registration" dir=out action=allow protocol=TCP localport=1515
```

### Required Ports
- **1514/tcp**: Agent-Manager communication
- **1515/tcp**: Agent registration (optional)
- **55000/tcp**: API communication (optional)

## Advanced Configuration

### Custom File Monitoring
Edit `ossec.conf` to add custom directories:
```xml
<localfile>
  <log_format>full_command</log_format>
  <location>C:\MyApp\logs\*.log</location>
</localfile>
```

### Registry Monitoring
```xml
<directories check_all="yes" realtime="yes">
  HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
</directories>
```

### Process Monitoring
```xml
<localfile>
  <log_format>eventlog</log_format>
  <location>Security</location>
</localfile>
```

## Deployment at Scale

### Group Policy Deployment
1. Create MSI installation package
2. Configure Group Policy Object
3. Deploy to target OUs
4. Monitor installation status

### PowerShell DSC
```powershell
Configuration MonitoringAgentDSC {
    Package MonitoringAgent {
        Name = "Monitoring Agent"
        Path = "\\server\share\monitoring-agent-4.13.1-1.msi"
        ProductId = "{PRODUCT-GUID}"
        Arguments = "MONITORING_MANAGER=192.168.1.100"
    }
}
```

### SCCM Deployment
1. Create SCCM Application
2. Configure detection methods
3. Set installation command line
4. Deploy to device collections

This comprehensive guide ensures successful deployment and operation of the Monitoring Agent across Windows environments with all features working correctly.