# Unified Windows Security Monitoring Agent
## RiskNoX Monitoring Agent + Suricata IDS + Supervisor Service

This package contains a complete Windows security monitoring solution that includes:
- **Wazuh-based Monitoring Agent**: File integrity monitoring, log analysis, and security event detection
- **Suricata Network IDS**: Network intrusion detection and traffic analysis  
- **RiskNoX Supervisor Service**: Service management and process supervision

## � **Windows Installer Package**

### **Quick Installation (Recommended)**

1. **Download**: `UnifiedSecurityAgent-1.0.0-Setup.exe`
2. **Run as Administrator**: Right-click → "Run as administrator"
3. **Follow Installation Wizard**: Select components and installation directory
4. **Automatic Setup**: Installer will automatically:
   - Install all components
   - Run `RiskNoXServiceControl.ps1 install` 
   - Run `RiskNoXServiceControl.ps1 start`
   - Start monitoring services immediately

### **What the Installer Does**

✅ **Installs Components**:
- Monitoring agent executables and libraries
- Suricata Network IDS with all dependencies
- RiskNoX Supervisor service
- Management tools and utilities

✅ **Configures System**:
- Creates Windows service: "RiskNoXSupervisor"
- Sets up automatic startup
- Applies security protections
- Creates Start Menu shortcuts

✅ **Starts Services Automatically**:
- Monitoring Agent (Wazuh-based)
- Suricata Network IDS
- Supervisor service management

## �🚀 Quick Start

### Installation & Setup

1. **Install Service** (Run as Administrator):
   ```powershell
   .\RiskNoXServiceControl.ps1 install
   ```

2. **Configure Agent**:
   ```powershell
   .\RiskNoXServiceControl.ps1 configure
   ```

3. **Start Service**:
   ```powershell
   .\RiskNoXServiceControl.ps1 start -Password "RiskNoX@2024"
   ```

4. **Check Status**:
   ```powershell
   .\RiskNoXServiceControl.ps1 status
   ```

## 📋 Components

### Core Executables
- `monitoring-agent.exe` - Main Wazuh monitoring agent
- `agent-auth.exe` - Agent authentication and enrollment
- `manage_agents.exe` - Agent management utility
- `supervisor.exe` - Process supervisor service

### Suricata Network IDS
- `suricata/bin/suricata.exe` - Network intrusion detection engine
- `suricata/etc/` - Configuration files
- `suricata/rules/` - Detection rules
- `suricata/log/` - Log output directory

### Management Scripts
- `RiskNoXServiceControl.ps1` - **Main service control script**
- `UnifiedAgentControl.ps1` - Agent configuration and enrollment
- `tools/` - Installation and management utilities

### Configuration
- `ossec.conf` - Main monitoring agent configuration
- `config/services.yml` - Supervisor service configuration
- `internal_options.conf` - Agent internal options
- `suricata/etc/suricata.yaml` - Suricata configuration

## 🔧 Service Management

The RiskNoX Supervisor manages two main processes:

1. **monitoring_agent** - Security monitoring and log analysis
2. **suricata_ids** - Network intrusion detection

### Available Commands

```powershell
# Service Management
.\RiskNoXServiceControl.ps1 install     # Install service and dependencies
.\RiskNoXServiceControl.ps1 configure   # Configure agent enrollment
.\RiskNoXServiceControl.ps1 start       # Start all services
.\RiskNoXServiceControl.ps1 stop        # Stop all services
.\RiskNoXServiceControl.ps1 status      # Show detailed status
.\RiskNoXServiceControl.ps1 restart     # Restart services

# Agent Configuration
.\UnifiedAgentControl.ps1 -Action configure   # Configure agent
.\UnifiedAgentControl.ps1 -Action status      # Show agent status
```

## 🛡️ Security Features

- **Service Protection**: Runs as LocalSystem with SDDL protection
- **Auto-Restart**: Automatic restart on process failure
- **Admin-Only Control**: Only administrators can stop the service
- **Password Protection**: Service operations require password authentication

## 📁 Directory Structure

```
monitoring-agent/
├── monitoring-agent.exe           # Main agent executable
├── RiskNoXServiceControl.ps1       # Service control script
├── UnifiedAgentControl.ps1         # Agent configuration
├── ossec.conf                      # Agent configuration
├── config/
│   └── services.yml               # Supervisor configuration
├── dist/
│   └── supervisor.exe             # Service supervisor
├── suricata/                      # Suricata IDS components
│   ├── bin/suricata.exe          # Suricata executable
│   ├── etc/suricata.yaml         # Suricata config
│   └── rules/                    # Detection rules
├── tools/                         # Management utilities
├── active-response/               # Active response scripts
├── ruleset/                       # Detection rules
└── logs/                         # Log files
```

## 🔍 Monitoring Capabilities

### File Integrity Monitoring (FIM)
- Real-time file and registry monitoring
- Checksum verification
- Change detection and alerting

### Log Analysis
- Windows Event Log monitoring
- Application log analysis
- Security event correlation

### Network Security (Suricata)
- Network traffic analysis
- Intrusion detection and prevention
- Protocol analysis and anomaly detection

### System Monitoring
- Process monitoring
- Service monitoring
- System configuration monitoring

## 📊 Log Files

- `logs/supervisor.log` - Service supervisor logs
- `logs/monitoring-agent.log` - Agent operation logs
- `suricata/log/` - Suricata detection and alert logs
- `ossec.log` - General OSSEC logs

## 🏗️ **Building the Installer**

### Prerequisites
- NSIS (Nullsoft Scriptable Install System) 3.08+
- All source files in the package directory

### Build Steps

1. **Validate Files**:
   ```powershell
   .\validate-installer-files.ps1 -Detailed
   ```

2. **Build Installer**:
   ```batch
   .\build-installer.bat
   ```

3. **Output**: `UnifiedSecurityAgent-1.0.0-Setup.exe`

### Installer Features
- Modern UI with component selection
- Administrator privilege validation
- PowerShell 7 detection (fallback to PowerShell 5.1)
- Automatic service installation and startup
- Complete uninstall capability
- Start Menu integration

## 🚨 Troubleshooting

### Service Won't Start
1. Check administrator privileges
2. Verify password: `RiskNoX@2024` (default)
3. Check logs: `logs/supervisor.log`
4. Verify installation: `.\RiskNoXServiceControl.ps1 status`

### Agent Not Enrolling
1. Check manager IP configuration
2. Verify network connectivity
3. Check agent-auth logs
4. Use: `.\UnifiedAgentControl.ps1 -Action configure`

### Suricata Issues
1. Check network interface availability
2. Verify WinDivert installation
3. Check Suricata logs: `suricata/log/suricata.log`
4. Verify rules: `suricata/rules/`

### Installer Issues
1. Run as Administrator
2. Check Windows version (Windows 10+ required)
3. Verify all source files present
4. Check NSIS installation

## 📞 Support

For support and troubleshooting:
1. Check service status: `.\RiskNoXServiceControl.ps1 status`
2. Review logs in `logs/` directory
3. Verify configuration files
4. Check Windows Event Logs

## 🔐 Default Credentials

- **Service Password**: `RiskNoX@2024`
- **Change Password**: Use `change-password.ps1` script

## ⚙️ System Requirements

- Windows 10 or later (64-bit)
- Administrator privileges for installation
- 2GB free disk space
- Internet connection for updates
- Network interface for Suricata monitoring
- PowerShell 5.1+ (PowerShell 7 recommended)

## 📋 **Installation Process**

The installer performs these steps automatically:

1. **System Validation**
   - Checks Windows version
   - Verifies administrator privileges
   - Detects PowerShell version

2. **File Installation**
   - Copies all components to installation directory
   - Sets appropriate file permissions
   - Creates directory structure

3. **Service Configuration**
   - Runs `RiskNoXServiceControl.ps1 install`
   - Installs Python dependencies
   - Builds supervisor executable
   - Creates Windows service

4. **Service Startup**
   - Runs `RiskNoXServiceControl.ps1 start`
   - Starts monitoring agent
   - Starts Suricata IDS
   - Verifies all processes running

5. **Registry Setup**
   - Creates uninstall entries
   - Sets up application paths
   - Configures Start Menu shortcuts

---

**Note**: This is a unified package containing both monitoring agent and network IDS capabilities. All components are managed through the RiskNoXServiceControl.ps1 script for centralized control. The installer provides a complete automated deployment solution.