#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Start RiskNoX Supervisor Service
#>

param([string]$ServiceName = "RiskNoXSupervisor")

function Write-Msg {
    param([string]$Message, [string]$Level = "INFO")
    $colors = @{ INFO = "Cyan"; SUCCESS = "Green"; ERROR = "Red"; WARN = "Yellow" }
    Write-Host "[$Level] $Message" -ForegroundColor $colors[$Level]
}

try {
    $service = Get-Service -Name $ServiceName -ErrorAction Stop
    
    if ($service.Status -eq 'Running') {
        Write-Msg "Service is already running" "INFO"
        exit 0
    }
    
    Write-Msg "Starting $ServiceName..." "INFO"
    Start-Service -Name $ServiceName
    Start-Sleep -Seconds 3
    
    $service = Get-Service -Name $ServiceName
    if ($service.Status -eq 'Running') {
        Write-Msg "Service started successfully" "SUCCESS"
        exit 0
    }
    else {
        Write-Msg "Service failed to start. Status: $($service.Status)" "ERROR"
        exit 1
    }
}
catch {
    Write-Msg "Error: $_" "ERROR"
    exit 1
}
