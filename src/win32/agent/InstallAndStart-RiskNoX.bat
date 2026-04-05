@echo off
REM ============================================================================
REM  RiskNoX Monitoring Agent - Install and Start
REM ============================================================================
REM  This batch file performs a complete installation and startup:
REM    1. Installs dependencies (Python, packages)
REM    2. Builds supervisor executable
REM    3. Installs Windows service with protection
REM    4. Starts the service with verification
REM
REM  Requirements:
REM    - Administrator privileges
REM    - Windows 10 or later
REM    - PowerShell 7+
REM
REM  Usage:
REM    Right-click -> Run as Administrator
REM    OR
REM    InstallAndStart-RiskNoX.bat
REM ============================================================================

setlocal EnableDelayedExpansion

REM Set default password (can be changed via command line)
set "SERVICE_PASSWORD=RiskNoX@2024"

REM Check for password argument
if not "%~1"=="" (
    set "SERVICE_PASSWORD=%~1"
)

echo.
echo ============================================================================
echo   RiskNoX Monitoring Agent - Install and Start
echo ============================================================================
echo.

REM Check for administrator privileges
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [ERROR] Administrator privileges required!
    echo.
    echo Please right-click this file and select "Run as Administrator"
    echo.
    pause
    exit /b 1
)

echo [INFO] Running with administrator privileges
echo.

REM Get the directory where this batch file is located
set "SCRIPT_DIR=%~dp0"
cd /d "%SCRIPT_DIR%"

echo [INFO] Working directory: %CD%
echo.

REM Check for PowerShell 7
where pwsh >nul 2>&1
if %errorLevel% neq 0 (
    echo [WARNING] PowerShell 7 not found in PATH, falling back to Windows PowerShell
    set "PS_CMD=powershell.exe"
) else (
    echo [INFO] Using PowerShell 7
    set "PS_CMD=pwsh"
)

REM ============================================================================
REM  STEP 1: INSTALLATION
REM ============================================================================

echo.
echo ========================================
echo   STEP 1: Installing Service
echo ========================================
echo.

echo [INFO] Executing: RiskNoXServiceControl.ps1 install
echo.

%PS_CMD% -ExecutionPolicy Bypass -NoProfile -File "%SCRIPT_DIR%RiskNoXServiceControl.ps1" install

if %errorLevel% neq 0 (
    echo.
    echo [ERROR] Installation failed!
    echo.
    echo Please check the logs at: logs\service-control.log
    echo.
    pause
    exit /b 1
)

echo.
echo [SUCCESS] Installation completed successfully!
echo.

REM ============================================================================
REM  STEP 2: START SERVICE
REM ============================================================================

echo.
echo ========================================
echo   STEP 2: Starting Service
echo ========================================
echo.

echo [INFO] Waiting 5 seconds before starting service...
timeout /t 5 /nobreak >nul

echo [INFO] Executing: RiskNoXServiceControl.ps1 start -Password ***
echo.

%PS_CMD% -ExecutionPolicy Bypass -NoProfile -Command "& '%SCRIPT_DIR%RiskNoXServiceControl.ps1' start -Password '%SERVICE_PASSWORD%'"

if %errorLevel% neq 0 (
    echo.
    echo [ERROR] Service start failed!
    echo.
    echo Possible reasons:
    echo   - Incorrect password (default: RiskNoX@2024)
    echo   - Service configuration error
    echo   - Dependencies not installed
    echo.
    echo Check status with: .\RiskNoXServiceControl.ps1 status
    echo Check logs at: logs\service-control.log
    echo.
    pause
    exit /b 1
)

echo.
echo [SUCCESS] Service started successfully!
echo.

REM ============================================================================
REM  STEP 3: VERIFY STATUS
REM ============================================================================

echo.
echo ========================================
echo   STEP 3: Verifying Status
echo ========================================
echo.

echo [INFO] Waiting 5 seconds for processes to initialize...
timeout /t 5 /nobreak >nul

echo [INFO] Checking service status...
echo.

%PS_CMD% -ExecutionPolicy Bypass -NoProfile -File "%SCRIPT_DIR%RiskNoXServiceControl.ps1" status

echo.
echo ============================================================================
echo   Installation and Startup Complete!
echo ============================================================================
echo.
echo   Service Status: RUNNING
echo   Protected:      YES (LocalSystem + SDDL)
echo   Auto-Start:     ENABLED
echo.
echo   Managed Processes:
echo     - backend_server           (Port 5000)
echo     - service_control_backend  (Port 8765)
echo     - monitoring_agent
echo     - suricata_ids
echo.
echo   Next Steps:
echo     1. Configure agent:  .\RiskNoXServiceControl.ps1 configure
echo     2. Check status:     .\RiskNoXServiceControl.ps1 status
echo     3. View logs:        logs\supervisor.log
echo.
echo   Management Commands:
echo     - Stop:              .\RiskNoXServiceControl.ps1 stop -Password "%SERVICE_PASSWORD%"
echo     - Restart:           .\RiskNoXServiceControl.ps1 restart -Password "%SERVICE_PASSWORD%"
echo     - Status:            .\RiskNoXServiceControl.ps1 status
echo.
echo   IMPORTANT:
echo     - Service is protected and cannot be stopped via Windows
echo     - Use the RiskNoXServiceControl.ps1 script for management
echo     - Service runs as LocalSystem with full privileges
echo     - Auto-restarts on failure with 0ms delay
echo.
echo ============================================================================
echo.

pause
exit /b 0