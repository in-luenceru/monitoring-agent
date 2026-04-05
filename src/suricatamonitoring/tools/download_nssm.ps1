# Download NSSM (Non-Sucking Service Manager)
# This script downloads NSSM for Windows service management

$ErrorActionPreference = "Stop"
$NSSM_VERSION = "2.24"
$NSSM_URL = "https://nssm.cc/release/nssm-$NSSM_VERSION.zip"
$TOOLS_DIR = $PSScriptRoot
$NSSM_DIR = Join-Path $TOOLS_DIR "nssm"
$NSSM_ZIP = Join-Path $TOOLS_DIR "nssm.zip"

function Write-Info {
    param([string]$Message)
    Write-Host "[INFO] $Message" -ForegroundColor Cyan
}

function Write-Success {
    param([string]$Message)
    Write-Host "[SUCCESS] $Message" -ForegroundColor Green
}

function Write-Err {
    param([string]$Message)
    Write-Host "[ERROR] $Message" -ForegroundColor Red
}

# Check if NSSM already exists
$nssmExe = Join-Path $NSSM_DIR "win64\nssm.exe"
if (Test-Path $nssmExe) {
    Write-Success "NSSM already exists: $nssmExe"
    exit 0
}

Write-Info "Downloading NSSM v$NSSM_VERSION..."

try {
    # Download NSSM
    Invoke-WebRequest -Uri $NSSM_URL -OutFile $NSSM_ZIP -UseBasicParsing
    Write-Success "Downloaded NSSM"
    
    # Extract
    Write-Info "Extracting NSSM..."
    Expand-Archive -Path $NSSM_ZIP -DestinationPath $TOOLS_DIR -Force
    
    # Rename directory
    $extractedDir = Join-Path $TOOLS_DIR "nssm-$NSSM_VERSION"
    if (Test-Path $extractedDir) {
        if (Test-Path $NSSM_DIR) {
            Remove-Item $NSSM_DIR -Recurse -Force
        }
        Rename-Item -Path $extractedDir -NewName "nssm"
    }
    
    # Clean up zip
    Remove-Item $NSSM_ZIP -Force
    
    # Verify
    if (Test-Path $nssmExe) {
        Write-Success "NSSM installed successfully: $nssmExe"
        & $nssmExe --version
    }
    else {
        Write-Err "NSSM installation failed"
        exit 1
    }
}
catch {
    Write-Err "Failed to download NSSM: $_"
    exit 1
}
