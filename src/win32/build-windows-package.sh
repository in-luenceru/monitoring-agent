#!/bin/bash

echo "================================================"
echo "   MONITORING AGENT WINDOWS PACKAGE BUILDER"
echo "================================================"
echo

# Get version and revision parameters
VERSION="$1"
REVISION="$2"

# If VERSION or REVISION are empty, ask for their value
if [ -z "$VERSION" ]; then
    read -p "Enter the version of the Monitoring agent (x.y.z): " VERSION
fi
if [ -z "$REVISION" ]; then
    read -p "Enter the revision of the Monitoring agent: " REVISION
fi

if [ -z "$VERSION" ]; then
    echo "ERROR: Version is required!"
    exit 1
fi
if [ -z "$REVISION" ]; then
    echo "ERROR: Revision is required!"
    exit 1
fi

PACKAGE_NAME="monitoring-agent-windows-${VERSION}-${REVISION}"
PACKAGE_DIR="${PACKAGE_NAME}"
ARCHIVE_NAME="${PACKAGE_NAME}.tar.gz"

echo "Building Windows package: $PACKAGE_NAME"
echo

# Clean up any existing package directory
if [ -d "$PACKAGE_DIR" ]; then
    echo "Removing existing package directory..."
    rm -rf "$PACKAGE_DIR"
fi

# Create package directory structure
echo "Creating package directory structure..."
mkdir -p "$PACKAGE_DIR"/{bin,config,docs,scripts}

# Check if required files exist
echo "Checking required files..."
REQUIRED_FILES=(
    "monitoring-agent.exe"
    "monitoring-agent-eventchannel.exe" 
    "manage_agents.exe"
    "agent-auth.exe"
    "setup-windows.exe"
    "default-ossec.conf"
    "internal_options.conf"
    "default-local_internal_options.conf"
)

MISSING_FILES=()
for file in "${REQUIRED_FILES[@]}"; do
    if [ -f "$file" ]; then
        echo "✓ $file found"
    else
        echo "✗ $file not found"
        MISSING_FILES+=("$file")
    fi
done

if [ ${#MISSING_FILES[@]} -gt 0 ]; then
    echo
    echo "ERROR: Missing required files:"
    printf '%s\n' "${MISSING_FILES[@]}"
    echo
    echo "Please build the agent first using: make TARGET=winagent"
    exit 1
fi

# Copy executables
echo
echo "Copying executables..."
cp *.exe "$PACKAGE_DIR/bin/" 2>/dev/null || true

# Copy configuration files
echo "Copying configuration files..."
cp default-ossec.conf "$PACKAGE_DIR/config/ossec.conf" 2>/dev/null || true
cp internal_options.conf "$PACKAGE_DIR/config/" 2>/dev/null || true
cp default-local_internal_options.conf "$PACKAGE_DIR/config/local_internal_options.conf" 2>/dev/null || true

# Copy documentation
echo "Copying documentation..."
[ -f "LICENSE.txt" ] && cp LICENSE.txt "$PACKAGE_DIR/docs/"
[ -f "VERSION.json" ] && cp VERSION.json "$PACKAGE_DIR/docs/"
[ -f "help_win.txt" ] && cp help_win.txt "$PACKAGE_DIR/docs/help.txt"

# Create installation script
echo "Creating installation scripts..."
cat > "$PACKAGE_DIR/scripts/install.bat" << 'EOF'
@echo off
echo Installing Monitoring Agent...

REM Check if running as administrator
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo ERROR: This script must be run as Administrator
    echo Right-click and select "Run as administrator"
    pause
    exit /b 1
)

REM Set installation directory
set INSTALL_DIR=C:\Program Files\MonitoringAgent
set SERVICE_NAME=MonitoringAgent

echo Creating installation directory: %INSTALL_DIR%
if not exist "%INSTALL_DIR%" mkdir "%INSTALL_DIR%"
if not exist "%INSTALL_DIR%\bin" mkdir "%INSTALL_DIR%\bin"
if not exist "%INSTALL_DIR%\config" mkdir "%INSTALL_DIR%\config"

echo Copying files...
copy /Y bin\*.exe "%INSTALL_DIR%\bin\"
copy /Y config\*.conf "%INSTALL_DIR%\config\"

echo Installing service...
"%INSTALL_DIR%\bin\monitoring-agent.exe" install-service

echo Configuring service...
sc config %SERVICE_NAME% start= auto
sc description %SERVICE_NAME% "Monitoring Agent for security monitoring and compliance"

echo Installation completed successfully!
echo.
echo Service name: %SERVICE_NAME%
echo Installation directory: %INSTALL_DIR%
echo.
echo To start the service: net start %SERVICE_NAME%
echo To configure: edit %INSTALL_DIR%\config\ossec.conf
echo.
pause
EOF

# Create uninstallation script
cat > "$PACKAGE_DIR/scripts/uninstall.bat" << 'EOF'
@echo off
echo Uninstalling Monitoring Agent...

REM Check if running as administrator
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo ERROR: This script must be run as Administrator
    echo Right-click and select "Run as administrator"
    pause
    exit /b 1
)

set INSTALL_DIR=C:\Program Files\MonitoringAgent
set SERVICE_NAME=MonitoringAgent

echo Stopping service...
sc stop %SERVICE_NAME% >nul 2>&1

echo Removing service...
sc delete %SERVICE_NAME% >nul 2>&1

echo Removing files...
if exist "%INSTALL_DIR%" (
    rmdir /S /Q "%INSTALL_DIR%"
    echo Files removed successfully
)

echo Uninstallation completed!
pause
EOF

# Create README
cat > "$PACKAGE_DIR/README.txt" << EOF
MONITORING AGENT WINDOWS PACKAGE v${VERSION}-${REVISION}
=====================================================

This package contains the Monitoring Agent for Windows systems.

CONTENTS:
--------
bin/                    - Executable files
├── monitoring-agent.exe                - Main agent service
├── monitoring-agent-eventchannel.exe   - Event channel collector
├── manage_agents.exe              - Agent management utility
├── agent-auth.exe                 - Agent authentication tool
└── setup-windows.exe              - Setup utility

config/                 - Configuration files
├── ossec.conf                     - Main configuration
├── internal_options.conf          - Internal options
└── local_internal_options.conf    - Local options

scripts/                - Installation scripts
├── install.bat                    - Installation script
└── uninstall.bat                  - Uninstallation script

docs/                   - Documentation
├── LICENSE.txt                    - License information
├── VERSION.json                   - Version details
└── help.txt                       - Help documentation

INSTALLATION:
------------
1. Extract this archive to a temporary directory
2. Right-click on scripts/install.bat and select "Run as administrator"
3. Follow the on-screen instructions
4. Configure the agent by editing C:\Program Files\MonitoringAgent\config\ossec.conf
5. Start the service: net start MonitoringAgent

UNINSTALLATION:
--------------
1. Right-click on scripts/uninstall.bat and select "Run as administrator"
2. Follow the on-screen instructions

CONFIGURATION:
-------------
Edit the configuration file at:
C:\Program Files\MonitoringAgent\config\ossec.conf

Key settings to configure:
- Server address/hostname
- Authentication keys
- Log files to monitor
- Active response settings

SERVICE MANAGEMENT:
------------------
Start service:    net start MonitoringAgent
Stop service:     net stop MonitoringAgent
Service status:   sc query MonitoringAgent

For more information, visit: https://documentation.monitoring.com/
EOF

# Create the archive
echo
echo "Creating archive: $ARCHIVE_NAME"
tar -czf "$ARCHIVE_NAME" "$PACKAGE_DIR"

if [ -f "$ARCHIVE_NAME" ]; then
    # Calculate sizes
    PACKAGE_SIZE=$(du -h "$PACKAGE_DIR" | cut -f1)
    ARCHIVE_SIZE=$(du -h "$ARCHIVE_NAME" | cut -f1)
    
    echo
    echo "================================================"
    echo "   SUCCESS: Windows Package Created!"
    echo "================================================"
    echo "Package: $PACKAGE_NAME"
    echo "Archive: $ARCHIVE_NAME"
    echo "Location: $(pwd)/$ARCHIVE_NAME"
    echo "Package size: $PACKAGE_SIZE"
    echo "Archive size: $ARCHIVE_SIZE"
    echo
    echo "Package contents:"
    echo "- Windows executables (*.exe)"
    echo "- Configuration files (*.conf)" 
    echo "- Installation/uninstallation scripts"
    echo "- Documentation and license"
    echo
    echo "To distribute:"
    echo "1. Transfer $ARCHIVE_NAME to Windows systems"
    echo "2. Extract the archive"
    echo "3. Run scripts/install.bat as Administrator"
    echo
    
    # Show package structure
    echo "Package structure:"
    tree "$PACKAGE_DIR" 2>/dev/null || find "$PACKAGE_DIR" -type f | sort
    
else
    echo "ERROR: Failed to create archive!"
    exit 1
fi

# Clean up package directory
echo
read -p "Remove temporary package directory? (Y/n): " CLEANUP
if [[ ! "$CLEANUP" =~ ^[Nn]$ ]]; then
    rm -rf "$PACKAGE_DIR"
    echo "Temporary directory cleaned up."
fi

echo "Build completed successfully!"