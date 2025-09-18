@echo off
REM Windows Monitoring Agent Bypass DLL Compilation Script
REM Copyright (C) 2025, Monitoring Solutions Inc.

echo Compiling Windows Monitoring Agent Bypass DLL...

REM Check for Visual Studio Build Tools
where cl.exe >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo ERROR: Visual Studio Build Tools not found. Please install Visual Studio Build Tools or Visual Studio.
    echo You can download it from: https://visualstudio.microsoft.com/downloads/
    echo.
    echo Alternatively, trying MinGW-w64 gcc...
    where gcc.exe >nul 2>&1
    if %ERRORLEVEL% NEQ 0 (
        echo ERROR: Neither Visual Studio nor MinGW-w64 found.
        echo Please install one of them to compile the bypass DLL.
        pause
        exit /b 1
    ) else (
        goto :compile_mingw
    )
)

REM Compile with Visual Studio
echo Using Visual Studio Build Tools...
cl.exe /LD /Fe:bypass.dll bypass_windows.c kernel32.lib advapi32.lib psapi.lib /DWIN32 /D_WINDOWS /D_USRDLL /D_WINDLL
if %ERRORLEVEL% EQU 0 (
    echo.
    echo ✓ Successfully compiled bypass.dll with Visual Studio
    goto :success
) else (
    echo.
    echo ✗ Compilation failed with Visual Studio
    goto :error
)

:compile_mingw
REM Compile with MinGW-w64
echo Using MinGW-w64 gcc...
gcc -shared -o bypass.dll bypass_windows.c -lkernel32 -ladvapi32 -lpsapi -DWIN32 -D_WINDOWS
if %ERRORLEVEL% EQU 0 (
    echo.
    echo ✓ Successfully compiled bypass.dll with MinGW-w64
    goto :success
) else (
    echo.
    echo ✗ Compilation failed with MinGW-w64
    goto :error
)

:success
echo.
echo Bypass DLL compilation completed successfully!
echo The bypass.dll file is ready for use.
echo.
echo To use the bypass DLL:
echo 1. Copy bypass.dll to the monitoring agent lib directory
echo 2. The PowerShell script will automatically detect and load it
echo 3. Set environment variable: set MONITORING_BYPASS_DLL=path\to\bypass.dll
echo.
echo For automatic loading on Windows:
echo - The DLL will be loaded when the monitoring agent starts
echo - Check logs\bypass.log for bypass activity
echo.
pause
exit /b 0

:error
echo.
echo Compilation failed. Please check the following:
echo 1. Visual Studio Build Tools or MinGW-w64 is properly installed
echo 2. The compiler is in your PATH
echo 3. You have proper permissions to write files
echo 4. The source file bypass_windows.c exists and is valid
echo.
pause
exit /b 1