#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Stop RiskNoX Supervisor Service
#>

param([string]$ServiceName = "RiskNoXSupervisor")

function Write-Msg {
    param([string]$Message, [string]$Level = "INFO")
    $colors = @{ INFO = "Cyan"; SUCCESS = "Green"; ERROR = "Red"; WARN = "Yellow" }
    Write-Host "[$Level] $Message" -ForegroundColor $colors[$Level]
}

try {
    $service = Get-Service -Name $ServiceName -ErrorAction Stop
    
    if ($service.Status -eq 'Stopped') {
        Write-Msg "Service is already stopped" "INFO"
        exit 0
    }
    
    Write-Msg "Stopping $ServiceName..." "INFO"
    Stop-Service -Name $ServiceName -Force
    Start-Sleep -Seconds 5
    
    $service = Get-Service -Name $ServiceName
    if ($service.Status -eq 'Stopped') {
        Write-Msg "Service stopped successfully" "SUCCESS"
        exit 0
    }
    else {
        Write-Msg "Service failed to stop. Status: $($service.Status)" "ERROR"
        exit 1
    }
}
catch {
    Write-Msg "Error: $_" "ERROR"
    exit 1
}
