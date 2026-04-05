@echo off
REM Build script for Unified Security Agent Installer
REM This script compiles the NSIS installer

echo ===============================================
echo   Unified Security Agent - Build Installer
echo ===============================================
echo.

REM Check if NSIS is installed
where makensis >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: NSIS (Nullsoft Scriptable Install System) not found!
    echo.
    echo Please install NSIS from: https://nsis.sourceforge.io/Download
    echo Add NSIS to your PATH or run this script from NSIS directory
    echo.
    pause
    exit /b 1
)

REM Check if installer script exists
if not exist "UnifiedSecurityAgent-Installer.nsi" (
    echo ERROR: UnifiedSecurityAgent-Installer.nsi not found!
    echo Please ensure you're running this script from the correct directory.
    echo.
    pause
    exit /b 1
)

REM Validate required files exist
echo Validating required files...
call :check_file "monitoring-agent.exe"
call :check_file "RiskNoXServiceControl.ps1"
call :check_file "UnifiedAgentControl.ps1"
call :check_file "suricata\bin\suricata.exe"
call :check_file "dist\supervisor.exe"
call :check_file "favicon.ico"
call :check_file "install.ico"
call :check_file "uninstall.ico"

if "%MISSING_FILES%" neq "" (
    echo.
    echo ERROR: Missing required files:
    echo %MISSING_FILES%
    echo.
    echo Please ensure all files are present before building the installer.
    pause
    exit /b 1
)

echo All required files found!
echo.

REM Create output directory
if not exist "build" mkdir build

REM Build the installer
echo Building installer...
makensis /DVERSION=1.0.0 "UnifiedSecurityAgent-Installer.nsi"

if %errorlevel% equ 0 (
    echo.
    echo ===============================================
    echo   BUILD SUCCESSFUL!
    echo ===============================================
    echo.
    echo Installer created: UnifiedSecurityAgent-1.0.0-Setup.exe
    echo.
    if exist "UnifiedSecurityAgent-1.0.0-Setup.exe" (
        echo File size: 
        for %%A in ("UnifiedSecurityAgent-1.0.0-Setup.exe") do echo   %%~zA bytes
        echo.
        echo The installer is ready for distribution!
        echo.
        echo To test the installer:
        echo   1. Run as Administrator: UnifiedSecurityAgent-1.0.0-Setup.exe
        echo   2. Follow the installation wizard
        echo   3. The service will start automatically after installation
        echo.
    ) else (
        echo Warning: Installer file not found after build
    )
) else (
    echo.
    echo ===============================================
    echo   BUILD FAILED!
    echo ===============================================
    echo.
    echo Check the error messages above for details.
    echo Common issues:
    echo   - Missing files
    echo   - Syntax errors in .nsi script
    echo   - Insufficient permissions
    echo.
)

pause
exit /b %errorlevel%

:check_file
if not exist "%~1" (
    set "MISSING_FILES=%MISSING_FILES% %~1"
)
goto :eof