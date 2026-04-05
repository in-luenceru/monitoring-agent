@echo off
setlocal enabledelayedexpansion

:: RiskNoX Monitoring Agent - Installer Build Script
:: This script builds the Windows installer using NSIS

echo ====================================================================
echo RiskNoX Monitoring Agent - Installer Build Script
echo ====================================================================
echo.

:: Check if NSIS is installed
set "NSIS_PATH="
if exist "C:\Program Files (x86)\NSIS\makensis.exe" (
    set "NSIS_PATH=C:\Program Files (x86)\NSIS\makensis.exe"
) else if exist "C:\Program Files\NSIS\makensis.exe" (
    set "NSIS_PATH=C:\Program Files\NSIS\makensis.exe"
) else (
    echo ERROR: NSIS (Nullsoft Scriptable Install System) not found!
    echo.
    echo Please install NSIS from: https://nsis.sourceforge.io/Download
    echo Install NSIS to the default location and try again.
    echo.
    pause
    exit /b 1
)

echo Found NSIS at: %NSIS_PATH%
echo.

:: Check if all required files are present
echo Checking required files...

set "MISSING_FILES="

:: Core executables
if not exist "monitoring-agent.exe" (
    set "MISSING_FILES=!MISSING_FILES! monitoring-agent.exe"
)
if not exist "backend_server.py" (
    set "MISSING_FILES=!MISSING_FILES! backend_server.py"
)
if not exist "RiskNoXServiceControl.ps1" (
    set "MISSING_FILES=!MISSING_FILES! RiskNoXServiceControl.ps1"
)
if not exist "UnifiedAgentControl.ps1" (
    set "MISSING_FILES=!MISSING_FILES! UnifiedAgentControl.ps1"
)

:: Configuration files
if not exist "ossec.conf" (
    set "MISSING_FILES=!MISSING_FILES! ossec.conf"
)
if not exist "VERSION.json" (
    set "MISSING_FILES=!MISSING_FILES! VERSION.json"
)

:: License file
if not exist "LICENSE" (
    echo WARNING: LICENSE file not found. Creating a default one...
    echo Creating LICENSE file...
    echo This software is provided as-is without warranty. > LICENSE
)

:: Tools directory
if not exist "tools\nssm\win64\nssm.exe" (
    set "MISSING_FILES=!MISSING_FILES! tools\nssm\win64\nssm.exe"
)

:: Supervisor
if not exist "dist\supervisor.exe" (
    set "MISSING_FILES=!MISSING_FILES! dist\supervisor.exe"
)

if not "!MISSING_FILES!"=="" (
    echo.
    echo ERROR: The following required files are missing:
    for %%f in (!MISSING_FILES!) do (
        echo   - %%f
    )
    echo.
    echo Please ensure all files are present before building the installer.
    echo.
    pause
    exit /b 1
)

echo All required files found.
echo.

:: Create output directory if it doesn't exist
if not exist "installer_output" (
    mkdir "installer_output"
)

:: Display build information
echo Build Information:
echo ------------------
echo Script: RiskNoX-Installer.nsi
echo Output: installer_output\RiskNoX-Monitoring-Agent-Installer.exe
echo NSIS: %NSIS_PATH%
echo.

:: Build the installer
echo Building installer...
echo.

"%NSIS_PATH%" /NOCD "RiskNoX-Installer.nsi"

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo ERROR: Installer build failed with error code %ERRORLEVEL%
    echo.
    echo Common issues:
    echo - Missing files referenced in the NSI script
    echo - NSIS syntax errors
    echo - Insufficient permissions
    echo.
    pause
    exit /b %ERRORLEVEL%
)

:: Check if installer was created
if exist "RiskNoX-Monitoring-Agent-Installer.exe" (
    :: Move to output directory
    move "RiskNoX-Monitoring-Agent-Installer.exe" "installer_output\"
    
    echo.
    echo ====================================================================
    echo BUILD SUCCESSFUL!
    echo ====================================================================
    echo.
    echo Installer created: installer_output\RiskNoX-Monitoring-Agent-Installer.exe
    
    :: Get file size
    for %%A in ("installer_output\RiskNoX-Monitoring-Agent-Installer.exe") do (
        set "FILE_SIZE=%%~zA"
    )
    
    :: Convert bytes to MB
    set /A FILE_SIZE_MB=!FILE_SIZE!/1024/1024
    
    echo File size: !FILE_SIZE_MB! MB
    echo.
    echo The installer includes:
    echo - Core monitoring agent components
    echo - Service supervisor system
    echo - Management tools and utilities
    echo - Active response system
    echo - Suricata network IDS
    echo - Configuration management
    echo - Automatic service installation
    echo.
    echo Installation Notes:
    echo - Requires Windows 10 or later (64-bit)
    echo - Requires administrator privileges
    echo - Installs to: C:\Program Files\RiskNoX\MonitoringAgent
    echo - Automatically configures Windows service
    echo - Creates Start Menu shortcuts
    echo.
    echo Next Steps:
    echo 1. Test the installer on a clean Windows system
    echo 2. Verify all components install correctly
    echo 3. Test service installation and startup
    echo 4. Validate agent enrollment and monitoring
    echo.
    
    :: Ask if user wants to open the output directory
    set /p OPEN_DIR="Open output directory? (y/n): "
    if /i "!OPEN_DIR!"=="y" (
        explorer "installer_output"
    )
    
) else (
    echo.
    echo ERROR: Installer file was not created!
    echo Check the NSIS build output above for errors.
    echo.
    pause
    exit /b 1
)

echo.
echo Build completed successfully!
pause