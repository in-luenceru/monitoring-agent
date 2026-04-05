#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Uninstall RiskNoX Supervisor Windows Service
#>

param(
    [string]$ServiceName = "RiskNoXSupervisor",
    [switch]$Force
)

$ErrorActionPreference = "Stop"
$NSSM_DIR = Join-Path $PSScriptRoot "nssm"
$NSSM_EXE = Join-Path $NSSM_DIR "win64\nssm.exe"

function Write-UninstallLog {
    param([string]$Message, [string]$Level = "INFO")
    $colors = @{ INFO = "Cyan"; SUCCESS = "Green"; ERROR = "Red"; WARN = "Yellow" }
    Write-Host "[$Level] $Message" -ForegroundColor $colors[$Level]
}

function Main {
    Write-UninstallLog "RiskNoX Supervisor Service Uninstaller" "INFO"
    Write-UninstallLog "=======================================" "INFO"
    
    # Check if service exists
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if (-not $service) {
        Write-UninstallLog "Service '$ServiceName' not found" "WARN"
        exit 0
    }
    
    # Confirm unless -Force
    if (-not $Force) {
        Write-Host ""
        Write-Host "WARNING: This will permanently remove the $ServiceName service" -ForegroundColor Yellow
        Write-Host "All managed processes will be stopped" -ForegroundColor Yellow
        Write-Host ""
        $confirmation = Read-Host "Type 'YES' to confirm uninstallation"
        
        if ($confirmation -ne 'YES') {
            Write-UninstallLog "Uninstallation cancelled" "WARN"
            exit 0
        }
    }
    
    try {
        # Stop service
        if ($service.Status -eq 'Running') {
            Write-UninstallLog "Stopping service..." "INFO"
            Stop-Service -Name $ServiceName -Force
            Start-Sleep -Seconds 5
            Write-UninstallLog "Service stopped" "SUCCESS"
        }
        
        # Remove service
        Write-UninstallLog "Removing service..." "INFO"
        
        if (Test-Path $NSSM_EXE) {
            & $NSSM_EXE remove $ServiceName confirm
        }
        else {
            # Fallback to sc.exe
            sc.exe delete $ServiceName
        }
        
        Start-Sleep -Seconds 2
        
        # Verify removal
        $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($service) {
            Write-UninstallLog "Service still exists after removal" "ERROR"
            exit 1
        }
        
        Write-UninstallLog "" "INFO"
        Write-UninstallLog "Service uninstalled successfully" "SUCCESS"
        Write-UninstallLog "" "INFO"
        Write-UninstallLog "Note: Configuration files and logs have been preserved" "INFO"
        Write-UninstallLog "To reinstall: .\tools\install_service.ps1" "INFO"
        
        exit 0
    }
    catch {
        Write-UninstallLog "Failed to uninstall service: $_" "ERROR"
        exit 1
    }
}

Main
