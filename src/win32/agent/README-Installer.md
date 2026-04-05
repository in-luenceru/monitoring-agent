# RiskNoX Monitoring Agent - Windows Installer

This directory contains the complete Windows installer package for the RiskNoX Monitoring Agent, built using NSIS (Nullsoft Scriptable Install System).

## 📦 Installer Overview

The installer creates a professional Windows installation package that includes:

- **Core Monitoring Components**: Main agent executable, backend services, and control systems
- **Service Management**: Automatic Windows service installation and configuration
- **Network Security**: Suricata IDS integration with rule sets
- **Configuration System**: Complete configuration management and enrollment tools
- **Management Tools**: PowerShell scripts for service control and monitoring
- **Active Response**: Automated threat response capabilities
- **Documentation**: User guides and configuration references

## 🛠️ Building the Installer

### Prerequisites

1. **NSIS (Nullsoft Scriptable Install System)**
   - Download from: https://nsis.sourceforge.io/Download
   - Install to default location (C:\Program Files (x86)\NSIS\)
   - Version 3.x recommended

2. **Required Files**
   - All agent binaries and DLLs must be present
   - PowerShell management scripts
   - Configuration files
   - Service supervisor components
   - Tools and utilities

### Build Methods

#### Method 1: PowerShell Script (Recommended)
```powershell
# Build with comprehensive checks
.\build-installer.ps1

# Build with verbose output
.\build-installer.ps1 -Verbose

# Skip pre-build checks (not recommended)
.\build-installer.ps1 -SkipChecks

# Custom output directory
.\build-installer.ps1 -OutputDir "custom_output"
```

#### Method 2: Batch Script
```cmd
# Simple build
build-installer.bat
```

#### Method 3: Manual NSIS Compilation
```cmd
# Direct NSIS compilation
"C:\Program Files (x86)\NSIS\makensis.exe" RiskNoX-Installer.nsi
```

## 📋 Installer Components

### Core Components (Required)
- `monitoring-agent.exe` - Main monitoring agent
- `backend_server.py` - Backend service
- `service_control_backend.py` - Service control API
- `RiskNoXServiceControl.ps1` - Primary service management
- `UnifiedAgentControl.ps1` - Agent configuration and enrollment
- DLL libraries (libwazuhext.dll, syscollector.dll, etc.)

### Service Supervisor
- `dist/supervisor.exe` - Process supervisor
- `supervisor/supervisor.py` - Supervisor Python script
- Service management and process monitoring

### Management Tools
- `tools/` directory with utilities
- `tools/nssm/` - Windows service wrapper
- PowerShell management scripts
- Configuration and deployment tools

### Security Components
- Suricata Network IDS
- Active Response System
- Detection rules and decoders
- Network packet capture (Npcap)

### Configuration System
- `config/` - Configuration files
- `ossec.conf` - Main configuration
- `internal_options.conf` - Internal settings
- Template files and samples

## 🎯 Installation Process

### What the Installer Does

1. **System Checks**
   - Verifies Windows 10+ (64-bit)
   - Checks administrator privileges
   - Validates system requirements

2. **File Installation**
   - Copies all components to `C:\Program Files\RiskNoX\MonitoringAgent`
   - Creates directory structure
   - Sets appropriate permissions

3. **Service Configuration**
   - Runs `RiskNoXServiceControl.ps1 install`
   - Installs Windows service
   - Configures automatic startup
   - Applies security protections

4. **Registry Setup**
   - Creates uninstall entries
   - Sets up application paths
   - Configures event log sources

5. **Start Menu Integration**
   - Creates Start Menu folder
   - Adds service management shortcuts
   - Links to documentation

### Installation Directory Structure
```
C:\Program Files\RiskNoX\MonitoringAgent\
├── Core executables and DLLs
├── config\                    # Configuration files
├── tools\                     # Management utilities
├── supervisor\                # Service supervisor
├── suricata\                  # Network IDS
├── active-response\           # Threat response
├── ruleset\                   # Detection rules
├── logs\                      # Log files
├── queue\                     # Message processing
├── shared\                    # Shared resources
└── state\                     # Runtime state
```

## 🚀 Post-Installation

### Automatic Service Installation

The installer automatically runs:
```powershell
.\RiskNoXServiceControl.ps1 install
```

This command:
- Installs Python dependencies
- Builds supervisor executable
- Creates Windows service
- Applies security protections
- Configures automatic restart

### Manual Configuration

After installation, configure the agent:
```powershell
# Navigate to installation directory
cd "C:\Program Files\RiskNoX\MonitoringAgent"

# Configure agent enrollment
.\RiskNoXServiceControl.ps1 configure

# Start the service
.\RiskNoXServiceControl.ps1 start

# Check status
.\RiskNoXServiceControl.ps1 status
```

## 🔧 Customization

### Modifying the Installer

1. **Edit NSI Script**: Modify `RiskNoX-Installer.nsi`
2. **Add Components**: Update file lists and sections
3. **Change Branding**: Update product information and icons
4. **Modify Installation Path**: Change `InstallDir` setting

### Component Selection

The installer includes component selection:
- **Core Components** (Required) - Essential monitoring agent
- **Configuration System** - Settings and configuration management  
- **Service Supervisor** - Process management and monitoring
- **Management Tools** - Administrative utilities
- **Active Response** - Automated threat response
- **Network Security** - Suricata IDS and network monitoring
- **Build System** (Optional) - Development and build tools

### Build Customization

Edit build scripts to:
- Change output directory
- Add file validation
- Include additional components
- Modify compression settings

## 📊 File Validation

### Required Files Check

The build script validates presence of:
- Core executables
- Essential DLLs
- PowerShell scripts
- Configuration files
- Service components
- Management tools

### Optional Components

The installer includes optional components if present:
- Suricata rules and configurations
- Sample configurations
- Development tools
- Additional utilities

## 🛡️ Security Features

### Service Protection

The installed service includes:
- LocalSystem privileges
- SDDL protection preventing unauthorized stop
- Automatic restart on failure
- Secure token-based control API

### File Permissions

Installer sets appropriate permissions:
- SYSTEM account full access
- Administrators group access
- Protected configuration files

## 🔍 Troubleshooting

### Build Issues

**NSIS Not Found**
- Install NSIS from official website
- Ensure installation in default location
- Check PATH environment variable

**Missing Files**
- Verify all required files are present
- Run with `-Verbose` for detailed file check
- Check build output for specific missing files

**Compilation Errors**
- Review NSI script syntax
- Check file paths in script
- Verify NSIS version compatibility

### Installation Issues

**Administrator Required**
- Run installer as administrator
- Right-click → "Run as administrator"

**Windows Version**
- Requires Windows 10 or later
- 64-bit Windows only

**Service Installation Fails**
- Check PowerShell execution policy
- Verify .NET Framework installed
- Review service installation logs

## 📚 Documentation

### Available Documentation

- `README-UnifiedControl.md` - Agent configuration guide
- `README-ServiceControl.md` - Service management guide
- `IMPLEMENTATION-SUMMARY.md` - Technical implementation details
- `PASSWORD-PROTECTION.md` - Security configuration guide

### Online Resources

- Project Website: https://risknox.com
- Support: support@risknox.com
- Documentation: https://docs.risknox.com

## 🔄 Uninstallation

The installer creates a complete uninstaller that:
- Stops and removes the service
- Removes all installed files
- Cleans registry entries
- Removes Start Menu shortcuts
- Preserves user configuration (optional)

Access via:
- Control Panel → Programs and Features
- Start Menu → RiskNoX → Uninstall
- Direct: `C:\Program Files\RiskNoX\MonitoringAgent\uninst.exe`

## 📝 Version Information

- **Installer Version**: 1.0.0
- **Agent Version**: As specified in VERSION.json
- **Build System**: NSIS 3.x
- **Target Platform**: Windows 10+ (64-bit)

## 🤝 Support

For installation or configuration issues:
1. Check the logs in the installation directory
2. Review documentation files
3. Contact support: support@risknox.com
4. Visit: https://risknox.com/support

---

**Note**: This installer is designed for production deployment of the RiskNoX Monitoring Agent. Ensure all components are properly tested before distribution.