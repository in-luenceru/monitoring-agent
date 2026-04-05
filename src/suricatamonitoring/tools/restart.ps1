#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Restart RiskNoX Supervisor Service
#>

param([string]$ServiceName = "RiskNoXSupervisor")

function Write-Msg {
    param([string]$Message, [string]$Level = "INFO")
    $colors = @{ INFO = "Cyan"; SUCCESS = "Green"; ERROR = "Red"; WARN = "Yellow" }
    Write-Host "[$Level] $Message" -ForegroundColor $colors[$Level]
}

try {
    $service = Get-Service -Name $ServiceName -ErrorAction Stop
    
    Write-Msg "Restarting $ServiceName..." "INFO"
    
    # Stop if running
    if ($service.Status -eq 'Running') {
        Write-Msg "Stopping service..." "INFO"
        Stop-Service -Name $ServiceName -Force
        Start-Sleep -Seconds 5
    }
    
    # Start
    Write-Msg "Starting service..." "INFO"
    Start-Service -Name $ServiceName
    Start-Sleep -Seconds 3
    
    $service = Get-Service -Name $ServiceName
    if ($service.Status -eq 'Running') {
        Write-Msg "Service restarted successfully" "SUCCESS"
        exit 0
    }
    else {
        Write-Msg "Service failed to restart. Status: $($service.Status)" "ERROR"
        exit 1
    }
}
catch {
    Write-Msg "Error: $_" "ERROR"
    exit 1
}
