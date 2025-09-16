@echo off
REM Windows compilation script for bypass DLL
REM Requires Visual Studio or MinGW-w64

echo Compiling Windows Bypass DLL...

REM Try Visual Studio first
where cl.exe >nul 2>&1
if %ERRORLEVEL% == 0 (
    echo Using Visual Studio compiler...
    cl.exe /LD /Fe:bypass_windows.dll bypass_windows.c advapi32.lib kernel32.lib user32.lib
    if %ERRORLEVEL% == 0 (
        echo Success! Windows bypass DLL compiled: bypass_windows.dll
        goto :test
    ) else (
        echo Visual Studio compilation failed
    )
)

REM Try MinGW-w64
where x86_64-w64-mingw32-gcc.exe >nul 2>&1
if %ERRORLEVEL% == 0 (
    echo Using MinGW-w64 compiler...
    x86_64-w64-mingw32-gcc.exe -Wall -O2 -shared -static-libgcc -o bypass_windows.dll bypass_windows.c -ladvapi32 -lkernel32 -luser32
    if %ERRORLEVEL% == 0 (
        echo Success! Windows bypass DLL compiled: bypass_windows.dll
        goto :test
    ) else (
        echo MinGW compilation failed
    )
)

REM Try standard gcc (if available)
where gcc.exe >nul 2>&1
if %ERRORLEVEL% == 0 (
    echo Using GCC compiler...
    gcc.exe -Wall -O2 -shared -o bypass_windows.dll bypass_windows.c -ladvapi32 -lkernel32 -luser32
    if %ERRORLEVEL% == 0 (
        echo Success! Windows bypass DLL compiled: bypass_windows.dll
        goto :test
    ) else (
        echo GCC compilation failed
    )
)

echo ERROR: No suitable compiler found!
echo Please install one of:
echo   - Visual Studio (with C++ tools)
echo   - MinGW-w64
echo   - GCC for Windows
goto :end

:test
echo.
echo Testing DLL...
if exist bypass_windows.dll (
    echo DLL file created successfully: bypass_windows.dll
    dir bypass_windows.dll
    echo.
    echo You can now test the monitoring agent with:
    echo   powershell.exe -ExecutionPolicy Bypass -File monitoring-agent-control.ps1 start
) else (
    echo ERROR: DLL file not found after compilation
)

:end
pause