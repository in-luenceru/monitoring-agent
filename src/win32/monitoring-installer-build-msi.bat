@echo off
SETLOCAL EnableDelayedExpansion

echo ================================================
echo   MONITORING AGENT MSI INSTALLER BUILD SCRIPT
echo ================================================
echo.

REM Set up paths for WiX Toolset and Windows SDK
SET PATH=%PATH%;C:\Program Files\Microsoft SDKs\Windows\v7.0\Bin
SET PATH=%PATH%;C:\Program Files (x86)\WiX Toolset v3.11\bin
SET PATH=%PATH%;C:\Program Files (x86)\WiX Toolset v3.10\bin
SET PATH=%PATH%;C:\Program Files (x86)\Windows Kits\10\bin\x86
SET PATH=%PATH%;C:\Program Files (x86)\Microsoft SDKs\Windows\v10.0A\bin\NETFX 4.8 Tools

REM Get version and revision parameters
set VERSION=%1
set REVISION=%2

REM IF VERSION or REVISION are empty, ask for their value
IF [%VERSION%] == [] (
    set /p VERSION=Enter the version of the Monitoring agent (x.y.z): 
)
IF [%REVISION%] == [] (
    set /p REVISION=Enter the revision of the Monitoring agent: 
)

IF [%VERSION%] == [] (
    echo ERROR: Version is required!
    goto :error
)
IF [%REVISION%] == [] (
    echo ERROR: Revision is required!
    goto :error
)

SET MSI_NAME=monitoring-agent-%VERSION%-%REVISION%.msi
echo Building MSI: %MSI_NAME%
echo.

REM Check if required files exist
echo Checking required files...
IF NOT EXIST "monitoring-installer.wxs" (
    echo ERROR: monitoring-installer.wxs not found!
    goto :error
)

IF NOT EXIST "monitoring-agent.exe" (
    echo ERROR: monitoring-agent.exe not found!
    echo Please build the agent first using: make TARGET=winagent
    goto :error
)

echo ✓ monitoring-installer.wxs found
echo ✓ monitoring-agent.exe found

REM Check for optional files
IF EXIST "monitoring-agent-eventchannel.exe" (
    echo ✓ monitoring-agent-eventchannel.exe found
) ELSE (
    echo ⚠ monitoring-agent-eventchannel.exe not found (optional)
)

echo.
echo Starting WiX compilation...

REM Compile the WiX source file
echo Step 1: Running candle.exe...
candle.exe -nologo "monitoring-installer.wxs" -out "monitoring-installer.wixobj" -ext WixUtilExtension -ext WixUiExtension -dProductVersion=%VERSION%
IF %ERRORLEVEL% NEQ 0 (
    echo ERROR: candle.exe failed with error code %ERRORLEVEL%
    goto :error
)
echo ✓ candle.exe completed successfully

REM Link the compiled object
echo Step 2: Running light.exe...
light.exe "monitoring-installer.wixobj" -out "%MSI_NAME%" -ext WixUtilExtension -ext WixUiExtension -spdb
IF %ERRORLEVEL% NEQ 0 (
    echo ERROR: light.exe failed with error code %ERRORLEVEL%
    goto :error
)
echo ✓ light.exe completed successfully

REM Clean up intermediate files
echo Step 3: Cleaning up intermediate files...
IF EXIST "monitoring-installer.wixobj" del "monitoring-installer.wixobj"
IF EXIST "simple.cab" del "simple.cab"

REM Check if MSI was created successfully
IF EXIST "%MSI_NAME%" (
    echo.
    echo ================================================
    echo   SUCCESS: MSI Package Created Successfully!
    echo ================================================
    echo File: %MSI_NAME%
    echo Location: %CD%\%MSI_NAME%
    echo Size: 
    dir "%MSI_NAME%" | findstr /C:"%MSI_NAME%"
    echo.
    echo Features included:
    echo - Monitoring Agent Service (MonitoringSvc)
    echo - File Integrity Monitoring
    echo - Log Collection and Analysis  
    echo - Security Event Detection
    echo - Policy and Compliance Monitoring
    echo - Active Response Capabilities
    echo - Windows Event Channel Support (if available)
    echo.
    echo Installation Command:
    echo msiexec /i "%MSI_NAME%" /quiet MONITORING_MANAGER="your-server" MONITORING_REGISTRATION_PASSWORD="your-password"
    echo.
) ELSE (
    echo ERROR: MSI package was not created!
    goto :error
)

REM Optional: Sign the MSI (uncomment if you have a code signing certificate)
 echo Step 4: Signing MSI package...
 signtool sign /a /tr http://timestamp.digicert.com /fd SHA256 /d "Monitoring Agent %VERSION%" /td SHA256 "%MSI_NAME%"
 IF %ERRORLEVEL% NEQ 0 (
     echo WARNING: Code signing failed with error code %ERRORLEVEL%
     echo The MSI package was created but is not digitally signed.
 ) ELSE (
     echo ✓ MSI package signed successfully
 )

goto :success

:error
echo.
echo ================================================
echo   BUILD FAILED!
echo ================================================
echo.
echo Common solutions:
echo 1. Install WiX Toolset from: https://wixtoolset.org/
echo 2. Build the agent first: make TARGET=winagent
echo 3. Ensure all paths are correct
echo 4. Run as Administrator if needed
echo.
pause
exit /b 1

:success
echo Build completed successfully!
echo.
pause
exit /b 0
