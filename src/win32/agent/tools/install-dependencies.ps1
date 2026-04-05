#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Install Dependencies for RiskNoX Supervisor Service
    
.DESCRIPTION
    Creates Python virtual environment and installs all required packages
    for the RiskNoX Supervisor Service. This must be run before building
    or installing the supervisor service.
    
.PARAMETER Force
    Force reinstallation even if .venv already exists
    
.EXAMPLE
    .\install-dependencies.ps1
    .\install-dependencies.ps1 -Force
    
.NOTES
    Requires Python 3.8+ and Administrator privileges
#>

param(
    [switch]$Force
)

$ErrorActionPreference = "Stop"
$AgentRoot = Split-Path $PSScriptRoot -Parent

# Color output functions
function Write-Info { param([string]$msg) Write-Host "[INFO] $msg" -ForegroundColor Cyan }
function Write-Success { param([string]$msg) Write-Host "[SUCCESS] $msg" -ForegroundColor Green }
function Write-Warning { param([string]$msg) Write-Host "[WARN] $msg" -ForegroundColor Yellow }
function Write-ErrorMsg { param([string]$msg) Write-Host "[ERROR] $msg" -ForegroundColor Red }

function Test-AdminRights {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-PythonInstalled {
    try {
        $pythonVersion = python --version 2>&1
        if ($pythonVersion -match "Python 3\.(8|9|10|11|12|13)") {
            Write-Success "Python found: $pythonVersion"
            return $true
        } else {
            Write-ErrorMsg "Python 3.8+ required. Found: $pythonVersion"
            return $false
        }
    }
    catch {
        Write-ErrorMsg "Python not found in PATH"
        Write-Warning "Python 3.8+ is required but not installed"
        Write-Host ""
        Write-Host "Would you like to download and install Python now? (Y/N): " -NoNewline -ForegroundColor Yellow
        $response = Read-Host
        
        if ($response -eq 'Y' -or $response -eq 'y') {
            Install-Python
            return Test-PythonInstalled  # Test again after installation
        } else {
            Write-ErrorMsg "Python installation declined"
            Write-Info "Download manually from: https://www.python.org/downloads/"
            Write-Info "During installation, check 'Add Python to PATH'"
            return $false
        }
    }
}

function Install-Python {
    Write-Info "Downloading Python 3.11 installer..."
    $pythonUrl = "https://www.python.org/ftp/python/3.11.9/python-3.11.9-amd64.exe"
    $installerPath = Join-Path $env:TEMP "python-3.11.9-installer.exe"
    
    try {
        Write-Info "This may take a few minutes depending on your internet speed..."
        Invoke-WebRequest -Uri $pythonUrl -OutFile $installerPath -UseBasicParsing
        Write-Success "Python installer downloaded"
        
        Write-Info "Installing Python 3.11 (silent install, this takes 2-3 minutes)..."
        Write-Info "IMPORTANT: Python will be added to PATH automatically"
        
        # Run installer with silent options: install for all users, add to PATH, install pip
        $installArgs = @(
            "/quiet",
            "InstallAllUsers=1",
            "PrependPath=1",
            "Include_pip=1",
            "Include_test=0"
        )
        
        $process = Start-Process -FilePath $installerPath -ArgumentList $installArgs -Wait -PassThru
        
        if ($process.ExitCode -eq 0) {
            Write-Success "Python installed successfully"
            Write-Info "Refreshing environment variables..."
            
            # Refresh PATH in current session
            $machinePath = [System.Environment]::GetEnvironmentVariable("Path", "Machine")
            $userPath = [System.Environment]::GetEnvironmentVariable("Path", "User")
            $env:Path = "$machinePath;$userPath"
            
            Start-Sleep -Seconds 2
        } else {
            Write-ErrorMsg "Python installation failed with exit code: $($process.ExitCode)"
            Write-Info "Please install Python manually from: https://www.python.org/downloads/"
        }
        
        # Cleanup
        Remove-Item $installerPath -Force -ErrorAction SilentlyContinue
    }
    catch {
        Write-ErrorMsg "Failed to download/install Python: $_"
        Write-Info "Please install Python manually from: https://www.python.org/downloads/"
    }
}

# Check admin rights
if (!(Test-AdminRights)) {
    Write-ErrorMsg "This script requires Administrator privileges"
    Write-Info "Right-click PowerShell and select 'Run as Administrator'"
    exit 1
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  RiskNoX Supervisor - Dependency Installer" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Step 1: Check Python
Write-Info "Step 1/5: Checking Python installation..."
if (!(Test-PythonInstalled)) {
    exit 1
}

# Step 2: Check/Create Virtual Environment
Write-Info "Step 2/5: Checking virtual environment..."
$venvPath = Join-Path $AgentRoot ".venv"

if (Test-Path $venvPath) {
    if ($Force) {
        Write-Warning "Removing existing virtual environment (Force mode)..."
        Remove-Item -Path $venvPath -Recurse -Force
    } else {
        Write-Warning "Virtual environment already exists: $venvPath"
        Write-Info "Use -Force to recreate it"
        
        # Verify it's functional
        $venvPython = Join-Path $venvPath "Scripts\python.exe"
        if (Test-Path $venvPython) {
            Write-Success "Virtual environment is functional"
        } else {
            Write-ErrorMsg "Virtual environment is corrupted"
            Write-Info "Run again with -Force to recreate"
            exit 1
        }
    }
}

if (!(Test-Path $venvPath)) {
    Write-Info "Creating Python virtual environment..."
    try {
        python -m venv $venvPath
        Write-Success "Virtual environment created: $venvPath"
    }
    catch {
        Write-ErrorMsg "Failed to create virtual environment: $_"
        exit 1
    }
}

# Step 3: Upgrade pip
Write-Info "Step 3/5: Upgrading pip..."
$venvPython = Join-Path $venvPath "Scripts\python.exe"
$venvPip = Join-Path $venvPath "Scripts\pip.exe"

try {
    & $venvPython -m pip install --upgrade pip --quiet 2>&1 | Out-Null
    Write-Success "pip upgraded successfully"
}
catch {
    Write-Warning "pip upgrade failed (non-critical): $_"
}

# Step 4: Install Dependencies
Write-Info "Step 4/5: Installing Python packages..."
$requirementsFile = Join-Path $AgentRoot "supervisor\requirements.txt"

if (!(Test-Path $requirementsFile)) {
    Write-ErrorMsg "Requirements file not found: $requirementsFile"
    Write-Info "Expected file structure:"
    Write-Info "  $AgentRoot\"
    Write-Info "    supervisor\"
    Write-Info "      requirements.txt"
    exit 1
}

Write-Info "Installing from: $requirementsFile"
try {
    & $venvPip install -r $requirementsFile --quiet 2>&1 | Out-Null
    Write-Success "All packages installed successfully"
}
catch {
    Write-ErrorMsg "Package installation failed: $_"
    Write-Info "Try running manually:"
    Write-Info "  cd `"$AgentRoot`""
    Write-Info "  .venv\Scripts\pip.exe install -r supervisor\requirements.txt"
    exit 1
}

# Step 6: Verify Installation
Write-Info "Step 5/5: Verifying installation..."
$requiredPackages = @(
    "pyyaml",
    "psutil",
    "flask",
    "flask-cors",
    "requests",
    "pywin32",
    "schedule",
    "pyinstaller"
)

$allInstalled = $true
foreach ($package in $requiredPackages) {
    try {
        $result = & $venvPip show $package 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Success "  ✓ $package"
        } else {
            Write-ErrorMsg "  ✗ $package - Not installed"
            $allInstalled = $false
        }
    }
    catch {
        Write-ErrorMsg "  ✗ $package - Verification failed"
        $allInstalled = $false
    }
}

Write-Host ""
if ($allInstalled) {
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "  ✅ INSTALLATION SUCCESSFUL!" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host ""
    Write-Success "Python environment ready at: $venvPath"
    Write-Info "Next steps:"
    Write-Info "  1. Build supervisor:  .\tools\build.ps1"
    Write-Info "  2. Install service:   .\tools\install_service.ps1"
    Write-Info "  3. Check status:      .\tools\status.ps1"
    Write-Host ""
    exit 0
} else {
    Write-Host "========================================" -ForegroundColor Red
    Write-Host "  ❌ INSTALLATION FAILED!" -ForegroundColor Red
    Write-Host "========================================" -ForegroundColor Red
    Write-Host ""
    Write-ErrorMsg "Some packages failed to install"
    Write-Info "Check error messages above for details"
    exit 1
}
