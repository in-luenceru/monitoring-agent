# RiskNoX Monitoring Agent - Windows Installer Documentation

## Professional Windows Installer for RiskNoX Monitoring Agent

This documentation covers the comprehensive Windows installer system created for the RiskNoX Monitoring Agent, providing enterprise-grade installation capabilities with Wazuh-style professional UI and complete component management.

---

## 📋 Table of Contents

- [Overview](#overview)
- [System Requirements](#system-requirements)
- [Quick Start](#quick-start)
- [File Structure](#file-structure)
- [Build Process](#build-process)
- [Installation Features](#installation-features)
- [PowerShell 7 Integration](#powershell-7-integration)
- [Component Details](#component-details)
- [Troubleshooting](#troubleshooting)
- [Advanced Usage](#advanced-usage)

---

## 🎯 Overview

The RiskNoX Monitoring Agent installer is a professional Windows installation package built with NSIS (Nullsoft Scriptable Install System). It provides:

- **Complete Agent Deployment**: All monitoring components, services, and dependencies
- **Professional UI**: Wazuh-style interface with detailed component descriptions
- **PowerShell 7 Integration**: Automatic detection and service management
- **Comprehensive Validation**: Pre-build file verification ensuring nothing is missed
- **Service Management**: Robust Windows service installation and configuration
- **Upgrade Support**: Intelligent upgrade detection and management
- **Enterprise Features**: Silent installation, logging, and administrative controls

---

## 🖥️ System Requirements

### Development System (Build Environment)
- **Operating System**: Windows 10/11 or Windows Server 2016+
- **NSIS**: Version 3.x with required plugins
- **PowerShell**: Version 5.1+ (PowerShell 7 recommended)
- **Disk Space**: 2GB for build environment
- **Memory**: 4GB RAM minimum

### Target Systems (Installation)
- **Operating System**: Windows 10/11, Windows Server 2016+
- **Architecture**: x64 (64-bit)
- **Privileges**: Administrator rights required
- **PowerShell**: Windows PowerShell 5.1 minimum (PowerShell 7 preferred)
- **Disk Space**: 500MB for complete installation
- **Memory**: 2GB RAM minimum

### Required NSIS Plugins
- **SimpleSC**: Windows service management
- **nsProcess**: Process management and termination
- **AccessControl**: File and registry permissions
- **Modern UI2 (MUI2)**: Professional installer interface

---

## 🚀 Quick Start

### Building the Installer

1. **Prepare Environment**
   ```powershell
   # Navigate to agent directory
   cd src\win32\agent
   
   # Verify all files are present
   .\validate-installer-files.ps1
   ```

2. **Build Installer**
   ```powershell
   # Standard build with validation
   .\build-installer.ps1
   
   # Detailed build with digital signing
   .\build-installer.ps1 -Detailed -Sign
   
   # Validation only (no build)
   .\build-installer.ps1 -ValidationOnly
   ```

3. **Install on Target System**
   ```powershell
   # Interactive installation
   .\RiskNoX-Agent-1.0.0-20241201-143022.exe
   
   # Silent installation
   .\RiskNoX-Agent-1.0.0-20241201-143022.exe /S
   
   # Silent with custom path
   .\RiskNoX-Agent-1.0.0-20241201-143022.exe /S /D=C:\MyCustomPath
   ```

---

## 📁 File Structure

### Build System Files
```
src/win32/agent/
├── RiskNoX-Installer.nsi          # Main NSIS installer script
├── build-installer.ps1            # Professional build script
├── validate-installer-files.ps1   # Comprehensive validation
├── build-installer.bat            # Batch wrapper for build
└── output/                        # Generated installers
```

### Agent Components (Installed)
```
C:\Program Files\RiskNoX Agent\
├── monitoring-agent.exe           # Main monitoring executable
├── agent-auth.exe                 # Authentication utility
├── manage_agents.exe              # Agent management tool
├── *.dll                          # Required libraries
├── *.ps1                          # PowerShell management scripts
├── config/                        # Configuration files
├── tools/                         # Management utilities
├── suricata/                      # Network IDS (optional)
├── npcap/                         # Network capture (optional)
├── logs/                          # Application logs
└── temp/                          # Temporary files
```

---

## 🔧 Build Process

### 1. Validation Phase
The build system performs comprehensive validation:

- **File Existence**: Verifies all required components are present
- **PowerShell Syntax**: Validates PowerShell script syntax
- **Executable Verification**: Checks binary file integrity
- **Size Analysis**: Reports component sizes and totals
- **Dependency Check**: Ensures all dependencies are available

### 2. Build Phase
Professional NSIS compilation:

- **Version Management**: Automatic version detection and embedding
- **Component Organization**: Structured file installation with proper permissions
- **Registry Integration**: Windows registry configuration
- **Service Setup**: Windows service registration and configuration
- **Shortcut Creation**: Start menu and desktop shortcuts

### 3. Post-Build Verification
Quality assurance steps:

- **Signature Verification**: Digital signature validation (if signed)
- **Executable Testing**: Basic functionality verification
- **Size Validation**: Final installer size verification
- **Command Line Testing**: Silent installation parameter testing

---

## 🎨 Installation Features

### Professional User Interface
- **Wazuh-Style Design**: Modern, professional appearance
- **Component Selection**: Optional components with detailed descriptions
- **Progress Tracking**: Real-time installation progress
- **Custom Branding**: RiskNoX branding and colors
- **Multi-language Ready**: Framework for localization

### Component Management
- **Core Agent**: Main monitoring service and utilities
- **Suricata IDS**: Network intrusion detection system
- **Npcap Driver**: Network packet capture capability
- **Management Tools**: Administrative utilities and scripts
- **Configuration**: Default and custom configuration templates

### Advanced Installation Options
- **Silent Installation**: Unattended deployment
- **Custom Paths**: User-defined installation directories
- **Service Configuration**: Automatic service setup and startup
- **Upgrade Detection**: Intelligent upgrade handling
- **Rollback Support**: Installation failure recovery

---

## ⚡ PowerShell 7 Integration

### Automatic Detection
The installer automatically detects PowerShell 7 installations:

```powershell
# Detection locations
$env:ProgramFiles\PowerShell\7\pwsh.exe
${env:ProgramFiles(x86)}\PowerShell\7\pwsh.exe
$env:LOCALAPPDATA\Microsoft\WindowsApps\pwsh.exe
```

### Fallback Mechanism
If PowerShell 7 is not available:
- Falls back to Windows PowerShell 5.1
- Displays informational message about PowerShell 7 benefits
- Continues installation without issues

### Service Installation
PowerShell script execution for service setup:
```powershell
# PowerShell 7 (preferred)
pwsh.exe -ExecutionPolicy Bypass -File "RiskNoXServiceControl.ps1" install

# Windows PowerShell 5.1 (fallback)
powershell.exe -ExecutionPolicy Bypass -File "RiskNoXServiceControl.ps1" install
```

---

## 📦 Component Details

### Core Executables
- **monitoring-agent.exe**: Primary monitoring service
- **agent-auth.exe**: Authentication and enrollment utility
- **manage_agents.exe**: Agent management interface
- **win32ui.exe**: Windows-specific UI components

### Dynamic Libraries
- **libwazuhshared.dll**: Core Wazuh functionality
- **libwazuhext.dll**: Extended monitoring capabilities
- **dbsync.dll**: Database synchronization
- **syscollector.dll**: System information collection
- **sysinfo.dll**: System information utilities

### PowerShell Management
- **RiskNoXServiceControl.ps1**: Primary service control
- **UnifiedAgentControl.ps1**: Unified management interface
- **MonitoringAgentControl.ps1**: Monitoring-specific controls
- **RiskNoX-Agent-Installer.ps1**: Installation utilities

### Configuration System
- **ossec.conf**: Main configuration file
- **internal_options.conf**: Internal configuration options
- **local_internal_options.conf**: Local customizations
- **vista_sec.txt**: Windows Vista+ security settings

### Optional Components
- **Suricata IDS**: Network intrusion detection
- **Npcap**: Network packet capture driver
- **Management Tools**: Advanced administrative utilities
- **Sample Configurations**: Example configurations and templates

---

## 🔍 Troubleshooting

### Common Build Issues

#### NSIS Not Found
```
Error: NSIS not found in standard installation locations
Solution: Install NSIS from https://nsis.sourceforge.io/Download
```

#### Missing Plugins
```
Warning: Missing NSIS plugins: SimpleSC.dll, nsProcess.dll
Solution: Download plugins from https://nsis.sourceforge.io/Category:Plugins
```

#### Validation Failures
```
Error: Required files missing - see validation output
Solution: Ensure all agent components are present in the directory
```

### Installation Issues

#### Service Installation Failure
```
Check: Administrator privileges
Check: Windows service permissions
Check: PowerShell execution policy
```

#### PowerShell Execution Errors
```
Solution: Set execution policy temporarily
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
```

#### Permission Denied Errors
```
Check: User Account Control (UAC) settings
Check: Antivirus software interference
Solution: Run installer as Administrator
```

### Runtime Issues

#### Service Won't Start
1. Check Windows Event Log for detailed errors
2. Verify all dependencies are installed
3. Check file permissions on installation directory
4. Validate configuration file syntax

#### Network Monitoring Issues
1. Verify Npcap driver installation
2. Check network adapter permissions
3. Validate Suricata configuration
4. Test network connectivity

---

## 🔧 Advanced Usage

### Custom Build Configuration

#### Environment Variables
```powershell
# Custom output directory
$env:RISKNOX_OUTPUT_DIR = "C:\CustomOutput"

# Custom version override
$env:RISKNOX_VERSION = "2.0.0-beta"

# Skip validation (not recommended)
$env:RISKNOX_SKIP_VALIDATION = "true"
```

#### Build Parameters
```powershell
# Professional build with all features
.\build-installer.ps1 -Detailed -Sign -OutputPath "C:\Releases\"

# Quick development build
.\build-installer.ps1 -SkipValidation

# Validation and testing only
.\build-installer.ps1 -ValidationOnly -Detailed
```

### Silent Deployment

#### Enterprise Deployment Script
```powershell
# Silent installation with logging
Start-Process -FilePath "RiskNoX-Agent-Installer.exe" -ArgumentList "/S", "/L=install.log" -Wait

# Verify installation
if (Get-Service "RiskNoXAgent" -ErrorAction SilentlyContinue) {
    Write-Host "Installation successful"
} else {
    Write-Error "Installation failed"
}
```

#### Group Policy Deployment
1. Copy installer to network share
2. Create Group Policy software installation package
3. Configure deployment settings for target computers
4. Monitor deployment through Group Policy reporting

### Custom Configuration

#### Pre-configured Installation
```powershell
# Create custom configuration
$customConfig = @{
    ServerAddress = "monitor.company.com"
    AgentName = "WORKSTATION-$env:COMPUTERNAME"
    LogLevel = "INFO"
}

# Deploy with custom configuration
.\RiskNoX-Agent-Installer.exe /S /CONFIG=custom.json
```

---

## 📚 Additional Resources

### Documentation Links
- [NSIS Documentation](https://nsis.sourceforge.io/Docs/)
- [PowerShell Documentation](https://docs.microsoft.com/en-us/powershell/)
- [Windows Services Guide](https://docs.microsoft.com/en-us/windows/win32/services/)

### Support and Community
- GitHub Issues: Report bugs and request features
- Documentation Wiki: Detailed technical documentation
- Community Forum: User discussions and support

### Professional Services
- Custom installer development
- Enterprise deployment consulting
- Training and certification programs

---

## 📄 License and Legal

This installer system is part of the RiskNoX Monitoring Agent and is subject to the same licensing terms. See LICENSE file for complete details.

**Digital Signatures**: For production deployment, ensure all executables and the installer itself are digitally signed with a valid code signing certificate.

**Security Considerations**: Always verify installer integrity before deployment in production environments. Use official distribution channels and validate digital signatures.

---

*Last Updated: December 2024*
*Version: 1.0.0*
*Maintainer: RiskNoX Development Team*