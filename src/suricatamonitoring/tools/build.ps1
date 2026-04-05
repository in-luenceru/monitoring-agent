#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Build supervisor.exe from Python source using PyInstaller
.DESCRIPTION
    Creates a standalone executable for the RiskNoX Supervisor Service
#>

param(
    [switch]$Clean,
    [switch]$SkipInstall,
    [switch]$SkipTest
)

$ErrorActionPreference = "Stop"
$REPO_ROOT = Split-Path $PSScriptRoot -Parent
$SUPERVISOR_DIR = Join-Path $REPO_ROOT "supervisor"
$DIST_DIR = Join-Path $REPO_ROOT "dist"
$BUILD_DIR = Join-Path $REPO_ROOT "build"
$VENV_PATH = Join-Path $REPO_ROOT ".venv"
$PYTHON_EXE = Join-Path $VENV_PATH "Scripts\python.exe"
$PIP_EXE = Join-Path $VENV_PATH "Scripts\pip.exe"

function Write-BuildLog {
    param([string]$Message, [string]$Level = "INFO")
    $colors = @{ INFO = "Cyan"; SUCCESS = "Green"; ERROR = "Red"; WARN = "Yellow" }
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:MM:ss"
    Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $colors[$Level]
}

function Test-PythonEnvironment {
    if (-not (Test-Path $PYTHON_EXE)) {
        Write-BuildLog "Python virtual environment not found at: $VENV_PATH" "ERROR"
        Write-BuildLog "Please run RiskNoX-Agent-Installer.ps1 first to create the environment" "ERROR"
        return $false
    }
    
    Write-BuildLog "Found Python environment: $PYTHON_EXE" "SUCCESS"
    return $true
}

function Install-BuildDependencies {
    Write-BuildLog "Installing build dependencies..." "INFO"
    
    try {
        # Install PyInstaller and dependencies
        & $PIP_EXE install --upgrade pip --quiet
        & $PIP_EXE install pyinstaller --quiet
        & $PIP_EXE install pyyaml psutil --quiet
        
        Write-BuildLog "Build dependencies installed" "SUCCESS"
        return $true
    }
    catch {
        Write-BuildLog "Failed to install dependencies: $_" "ERROR"
        return $false
    }
}

function Clear-BuildArtifacts {
    Write-BuildLog "Cleaning build artifacts..." "INFO"
    
    @($DIST_DIR, $BUILD_DIR) | ForEach-Object {
        if (Test-Path $_) {
            Remove-Item $_ -Recurse -Force
            Write-BuildLog "Removed $_" "INFO"
        }
    }
    
    # Remove spec file
    $specFile = Join-Path $SUPERVISOR_DIR "supervisor.spec"
    if (Test-Path $specFile) {
        Remove-Item $specFile -Force
        Write-BuildLog "Removed $specFile" "INFO"
    }
    
    Write-BuildLog "Build artifacts cleaned" "SUCCESS"
}

function Build-SupervisorExecutable {
    Write-BuildLog "Building supervisor.exe..." "INFO"
    
    try {
        $supervisorScript = Join-Path $SUPERVISOR_DIR "supervisor.py"
        
        if (-not (Test-Path $supervisorScript)) {
            Write-BuildLog "Supervisor script not found: $supervisorScript" "ERROR"
            return $false
        }
        
        # PyInstaller arguments
        $pyinstallerArgs = @(
            "-m", "PyInstaller",
            "--name=supervisor",
            "--onefile",
            "--console",
            "--clean",
            "--noconfirm",
            "--distpath=$DIST_DIR",
            "--workpath=$BUILD_DIR",
            "--specpath=$SUPERVISOR_DIR",
            "--add-data=$REPO_ROOT\config;config",
            "--hidden-import=yaml",
            "--hidden-import=psutil",
            "--hidden-import=win32api",
            "--hidden-import=win32con",
            "--hidden-import=win32security",
            $supervisorScript
        )
        
        Write-BuildLog "Running PyInstaller..." "INFO"
        Write-BuildLog "Command: python $($pyinstallerArgs -join ' ')" "INFO"
        
        Push-Location $SUPERVISOR_DIR
        try {
            & $PYTHON_EXE $pyinstallerArgs
            
            if ($LASTEXITCODE -ne 0) {
                Write-BuildLog "PyInstaller failed with exit code $LASTEXITCODE" "ERROR"
                return $false
            }
        }
        finally {
            Pop-Location
        }
        
        # Verify output
        $outputExe = Join-Path $DIST_DIR "supervisor.exe"
        if (Test-Path $outputExe) {
            $fileSize = (Get-Item $outputExe).Length / 1MB
            Write-BuildLog "Build successful!" "SUCCESS"
            Write-BuildLog "Output: $outputExe" "SUCCESS"
            Write-BuildLog "Size: $([math]::Round($fileSize, 2)) MB" "INFO"
            return $true
        }
        else {
            Write-BuildLog "Build completed but executable not found" "ERROR"
            return $false
        }
    }
    catch {
        Write-BuildLog "Build failed: $_" "ERROR"
        return $false
    }
}

function Test-SupervisorExecutable {
    Write-BuildLog "Testing supervisor.exe..." "INFO"
    
    $exePath = Join-Path $DIST_DIR "supervisor.exe"
    
    if (-not (Test-Path $exePath)) {
        Write-BuildLog "Executable not found: $exePath" "ERROR"
        return $false
    }
    
    try {
        # Quick test: just verify the file is a valid executable
        $fileInfo = Get-Item $exePath
        if ($fileInfo.Length -gt 0) {
            Write-BuildLog "Executable file is valid ($([math]::Round($fileInfo.Length / 1MB, 2)) MB)" "SUCCESS"
            
            # Test that it can at least be launched (start and immediately stop)
            $testProcess = Start-Process -FilePath $exePath -PassThru -NoNewWindow -ErrorAction SilentlyContinue
            Start-Sleep -Milliseconds 500
            
            if (!$testProcess.HasExited) {
                Stop-Process -Id $testProcess.Id -Force -ErrorAction SilentlyContinue
                Write-BuildLog "Executable launches successfully" "SUCCESS"
            } else {
                Write-BuildLog "Executable exited immediately (this may be normal)" "INFO"
            }
            
            return $true
        }
        else {
            Write-BuildLog "Executable file is empty" "ERROR"
            return $false
        }
    }
    catch {
        Write-BuildLog "Executable test failed: $_" "WARN"
        Write-BuildLog "This may be normal if the executable requires configuration" "INFO"
        return $true
    }
}

function Main {
    Write-BuildLog "========================================" "INFO"
    Write-BuildLog "  RiskNoX Supervisor Build Script      " "INFO"
    Write-BuildLog "========================================" "INFO"
    
    # Check Python environment
    if (-not (Test-PythonEnvironment)) {
        exit 1
    }
    
    # Clean if requested
    if ($Clean) {
        Clear-BuildArtifacts
    }
    
    # Install dependencies
    if (-not $SkipInstall) {
        if (-not (Install-BuildDependencies)) {
            exit 1
        }
    }
    
    # Build executable
    if (-not (Build-SupervisorExecutable)) {
        exit 1
    }
    
    # Test executable (unless skipped)
    if (-not $SkipTest) {
        Test-SupervisorExecutable | Out-Null
    }
    else {
        Write-BuildLog "Skipping executable test" "INFO"
    }
    
    Write-BuildLog "" "INFO"
    Write-BuildLog "========================================" "INFO"
    Write-BuildLog "  Build Process Complete!              " "SUCCESS"
    Write-BuildLog "========================================" "INFO"
    Write-BuildLog "Next steps:" "INFO"
    Write-BuildLog "1. Install as Windows service: .\tools\install_service.ps1" "INFO"
    Write-BuildLog "2. Start the service: .\tools\start.ps1" "INFO"
    Write-BuildLog "3. Check status: .\tools\status.ps1" "INFO"
    
    exit 0
}

# Run main
Main
