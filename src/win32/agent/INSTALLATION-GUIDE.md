# RiskNoX Monitoring Agent - Installation Guide

Welcome to the RiskNoX Monitoring Agent installation guide. This document will walk you through the complete installation and configuration process.

## 🎯 Overview

The RiskNoX Monitoring Agent is a comprehensive security monitoring solution that provides:

- **Real-time System Monitoring** - File integrity, process monitoring, and system activity tracking
- **Network Security** - Intrusion detection with Suricata IDS
- **Active Response** - Automated threat response and mitigation
- **Centralized Management** - Remote configuration and monitoring capabilities
- **Service Protection** - Advanced service protection against tampering

## 💻 System Requirements

### Minimum Requirements
- **Operating System**: Windows 10 (64-bit) or later
- **Processor**: Intel Core i3 or AMD equivalent (2.0 GHz+)
- **Memory**: 4 GB RAM
- **Storage**: 2 GB free disk space
- **Network**: Internet connection for updates and reporting
- **Privileges**: Administrator access required

### Recommended Requirements
- **Operating System**: Windows 11 (64-bit)
- **Processor**: Intel Core i5 or AMD equivalent (2.5 GHz+)
- **Memory**: 8 GB RAM or more
- **Storage**: 5 GB free disk space
- **Network**: Broadband internet connection

### Supported Windows Versions
- ✅ Windows 11 (all editions)
- ✅ Windows 10 (version 1909 or later)
- ✅ Windows Server 2019
- ✅ Windows Server 2022
- ❌ Windows 8.1 and earlier (not supported)
- ❌ 32-bit Windows (not supported)

## 📥 Installation Process

### Step 1: Download the Installer

1. Download `RiskNoX-Monitoring-Agent-Installer.exe`
2. Verify the file integrity (if provided with checksum)
3. Ensure the file is not blocked by Windows

### Step 2: Prepare for Installation

1. **Close Other Applications**: Close any unnecessary applications
2. **Disable Antivirus Temporarily**: Some antivirus software may interfere
3. **Backup Important Data**: Although not required, backing up is recommended
4. **Check Disk Space**: Ensure at least 2 GB free space

### Step 3: Run the Installer

1. **Right-click** the installer file
2. Select **"Run as administrator"**
3. If prompted by User Account Control (UAC), click **"Yes"**

### Step 4: Installation Wizard

#### Welcome Screen
- Read the welcome message
- Click **"Next"** to continue

#### License Agreement
- Read the End User License Agreement (EULA)
- Check **"I agree to the license terms and conditions"**
- Click **"Next"**

#### Installation Directory
- Default: `C:\Program Files\RiskNoX\MonitoringAgent`
- Change if desired (not recommended)
- Click **"Next"**

#### Start Menu Folder
- Default: `RiskNoX Monitoring Agent`
- Modify if desired
- Click **"Next"**

#### Component Selection
Select components to install:

- ✅ **Core Monitoring Agent** (Required)
- ✅ **Configuration System** (Recommended)
- ✅ **Service Supervisor** (Recommended)
- ✅ **Management Tools** (Recommended)
- ✅ **Active Response** (Recommended)
- ✅ **Network Security (Suricata)** (Recommended)
- ⚪ **Build System** (Optional - for developers)

#### Installation Progress
- Wait for installation to complete
- This may take 2-5 minutes depending on selected components

#### Finish
- Choose whether to start service configuration
- Click **"Finish"**

## ⚙️ Post-Installation Configuration

### Automatic Service Installation

The installer automatically runs the service installation:
```
RiskNoXServiceControl.ps1 install
```

This process:
1. Installs Python dependencies
2. Builds the service supervisor
3. Creates Windows service
4. Applies security protections
5. Configures automatic startup

### Agent Configuration

After installation, configure the monitoring agent:

1. **Open PowerShell as Administrator**
2. **Navigate to installation directory**:
   ```powershell
   cd "C:\Program Files\RiskNoX\MonitoringAgent"
   ```

3. **Configure agent enrollment**:
   ```powershell
   .\RiskNoXServiceControl.ps1 configure
   ```

4. **Start the service**:
   ```powershell
   .\RiskNoXServiceControl.ps1 start -Password "RiskNoX@2024"
   ```

5. **Verify service status**:
   ```powershell
   .\RiskNoXServiceControl.ps1 status
   ```

### Start Menu Shortcuts

The installer creates the following shortcuts:

- **RiskNoX Service Control** - Service management interface
- **RiskNoX Agent Control** - Agent configuration interface
- **Configuration Guide** - Documentation and guides
- **Installation Folder** - Direct access to installation directory

## 🔧 Configuration Options

### Basic Configuration

The agent uses several configuration files:

- **`ossec.conf`** - Main agent configuration
- **`internal_options.conf`** - Internal agent options
- **`config/services.yml`** - Service configuration
- **`config/settings.json`** - Application settings

### Network Configuration

Configure network settings for communication:

1. **Manager Connection**: Set manager IP/hostname
2. **Port Configuration**: Configure communication ports
3. **SSL/TLS Settings**: Configure secure communication
4. **Firewall Rules**: Ensure required ports are open

### Monitoring Configuration

Configure what to monitor:

1. **File Integrity Monitoring (FIM)**: Specify files/directories to monitor
2. **Log Collection**: Configure log sources
3. **Process Monitoring**: Enable process tracking
4. **Network Monitoring**: Configure network interface monitoring

## 🛡️ Security Features

### Service Protection

The installed service includes advanced protection:

- **LocalSystem Privileges**: Runs with highest system privileges
- **SDDL Protection**: Prevents unauthorized service stopping
- **Automatic Restart**: Restarts automatically if stopped or crashes
- **Tamper Protection**: Protects against modification attempts

### Password Protection

The service uses password protection:
- **Default Password**: `RiskNoX@2024`
- **Change Password**: Use the password change utility
- **Strong Authentication**: Required for service operations

### Network Security

Network monitoring includes:
- **Suricata IDS**: Network intrusion detection
- **Traffic Analysis**: Network traffic monitoring
- **Threat Detection**: Real-time threat identification
- **Automated Response**: Configurable response actions

## 📊 Monitoring and Management

### Service Status

Check service status regularly:
```powershell
.\RiskNoXServiceControl.ps1 status
```

This shows:
- Service running state
- Managed process status
- Port availability
- Agent enrollment status
- Recent activity

### Log Files

Monitor these log files:
- **`logs/supervisor.log`** - Service supervisor logs
- **`logs/backend_server_stdout.log`** - Backend service logs
- **`logs/monitoring_agent_stdout.log`** - Agent logs
- **`suricata/log/suricata.log`** - Network IDS logs

### Performance Monitoring

Monitor system performance:
- **CPU Usage**: Normal operation should use <5% CPU
- **Memory Usage**: Typical usage 100-300 MB RAM
- **Disk Usage**: Log rotation prevents excessive disk usage
- **Network Usage**: Minimal impact on network performance

## 🔄 Maintenance

### Regular Tasks

Perform these maintenance tasks:

1. **Check Service Status** (Daily):
   ```powershell
   .\RiskNoXServiceControl.ps1 status
   ```

2. **Review Logs** (Weekly):
   - Check for errors or warnings
   - Monitor agent connectivity
   - Review security events

3. **Update Configuration** (As needed):
   - Modify monitoring rules
   - Update network settings
   - Adjust security policies

### Updates and Upgrades

Keep the agent updated:
1. **Check for Updates**: Monitor for new releases
2. **Backup Configuration**: Before updating
3. **Stop Service**: Before installing updates
4. **Install Update**: Run new installer
5. **Restore Configuration**: If needed
6. **Restart Service**: After update

## 🚨 Troubleshooting

### Common Issues

#### Service Won't Start
**Symptoms**: Service fails to start
**Solutions**:
1. Check administrator privileges
2. Verify all files are present
3. Check Windows Event Log
4. Review service logs
5. Restart as administrator

#### Agent Connection Issues
**Symptoms**: Agent can't connect to manager
**Solutions**:
1. Verify network connectivity
2. Check firewall settings
3. Validate manager configuration
4. Review authentication settings
5. Check SSL certificates

#### High CPU Usage
**Symptoms**: Excessive CPU consumption
**Solutions**:
1. Check monitoring configuration
2. Reduce scan frequency
3. Exclude unnecessary files
4. Review active processes
5. Restart service

#### Permission Errors
**Symptoms**: Access denied errors
**Solutions**:
1. Run as administrator
2. Check file permissions
3. Verify service account rights
4. Review UAC settings
5. Check antivirus exclusions

### Getting Help

If you need assistance:

1. **Check Documentation**: Review included guides
2. **Check Logs**: Look for error messages
3. **Search Knowledge Base**: Visit support website
4. **Contact Support**: Email support team

### Support Information

- **Website**: https://risknox.com
- **Support Email**: support@risknox.com
- **Documentation**: https://docs.risknox.com
- **Knowledge Base**: https://kb.risknox.com

## 🗑️ Uninstallation

To remove the RiskNoX Monitoring Agent:

### Method 1: Control Panel
1. Open **Control Panel**
2. Go to **Programs and Features**
3. Find **RiskNoX Monitoring Agent**
4. Click **Uninstall**
5. Follow the uninstall wizard

### Method 2: Start Menu
1. Open **Start Menu**
2. Go to **RiskNoX Monitoring Agent**
3. Click **Uninstall**
4. Follow the uninstall wizard

### Method 3: Direct
1. Navigate to installation directory
2. Run **uninst.exe**
3. Follow the uninstall wizard

### Complete Removal

The uninstaller:
- Stops and removes the Windows service
- Removes all installed files and directories
- Cleans registry entries
- Removes Start Menu shortcuts
- Preserves user configuration (optional)

## 📋 Quick Reference

### Essential Commands

```powershell
# Navigate to installation directory
cd "C:\Program Files\RiskNoX\MonitoringAgent"

# Install service
.\RiskNoXServiceControl.ps1 install

# Configure agent
.\RiskNoXServiceControl.ps1 configure

# Start service (requires password)
.\RiskNoXServiceControl.ps1 start -Password "RiskNoX@2024"

# Check status
.\RiskNoXServiceControl.ps1 status

# Stop service (requires password)
.\RiskNoXServiceControl.ps1 stop -Password "RiskNoX@2024"

# Restart service
.\RiskNoXServiceControl.ps1 restart -Password "RiskNoX@2024"
```

### Important File Locations

- **Installation Directory**: `C:\Program Files\RiskNoX\MonitoringAgent`
- **Configuration Files**: `C:\Program Files\RiskNoX\MonitoringAgent\config`
- **Log Files**: `C:\Program Files\RiskNoX\MonitoringAgent\logs`
- **Service Executable**: `C:\Program Files\RiskNoX\MonitoringAgent\dist\supervisor.exe`

### Default Settings

- **Service Name**: `RiskNoXSupervisor`
- **Default Password**: `RiskNoX@2024`
- **Control API Port**: `8080`
- **Service Account**: `LocalSystem`
- **Startup Type**: `Automatic`

---

## 🎉 Congratulations!

You have successfully installed the RiskNoX Monitoring Agent. The system is now actively monitoring your environment and providing security protection.

For additional configuration options and advanced features, please refer to the detailed documentation included with the installation.

**Welcome to enhanced security monitoring with RiskNoX!**