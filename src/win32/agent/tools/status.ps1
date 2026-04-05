<#
.SYNOPSIS
    Check RiskNoX Supervisor Service Status
#>

param([string]$ServiceName = "RiskNoXSupervisor")

function Write-Msg {
    param([string]$Message, [string]$Level = "INFO")
    $colors = @{ INFO = "Cyan"; SUCCESS = "Green"; ERROR = "Red"; WARN = "Yellow" }
    Write-Host "[$Level] $Message" -ForegroundColor $colors[$Level]
}

try {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host " RiskNoX Supervisor Service Status" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    
    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    
    if (-not $service) {
        Write-Msg "Service not installed" "ERROR"
        Write-Host ""
        Write-Host "To install: .\tools\install_service.ps1" -ForegroundColor Yellow
        exit 1
    }
    
    # Service info
    Write-Host "Service Name:    " -NoNewline -ForegroundColor Gray
    Write-Host $service.Name -ForegroundColor White
    
    Write-Host "Display Name:    " -NoNewline -ForegroundColor Gray
    Write-Host $service.DisplayName -ForegroundColor White
    
    Write-Host "Status:          " -NoNewline -ForegroundColor Gray
    $statusColor = if ($service.Status -eq 'Running') { 'Green' } else { 'Red' }
    Write-Host $service.Status -ForegroundColor $statusColor
    
    Write-Host "Startup Type:    " -NoNewline -ForegroundColor Gray
    Write-Host $service.StartType -ForegroundColor White
    
    # Get process info if running
    if ($service.Status -eq 'Running') {
        try {
            $process = Get-Process | Where-Object { $_.ProcessName -eq 'supervisor' } | Select-Object -First 1
            if ($process) {
                Write-Host "PID:             " -NoNewline -ForegroundColor Gray
                Write-Host $process.Id -ForegroundColor White
                
                $uptime = (Get-Date) - $process.StartTime
                Write-Host "Uptime:          " -NoNewline -ForegroundColor Gray
                Write-Host "$($uptime.Days)d $($uptime.Hours)h $($uptime.Minutes)m" -ForegroundColor White
                
                $memoryMB = [math]::Round($process.WorkingSet64 / 1MB, 2)
                Write-Host "Memory:          " -NoNewline -ForegroundColor Gray
                Write-Host "$memoryMB MB" -ForegroundColor White
            }
        }
        catch {}
    }
    
    Write-Host ""
    
    # Check managed processes via control API
    try {
        $REPO_ROOT = Split-Path $PSScriptRoot -Parent
        $tokenFile = Join-Path $REPO_ROOT "config\supervisor_token.txt"
        
        if (Test-Path $tokenFile) {
            $token = Get-Content $tokenFile -Raw
            $token = $token.Trim()
            
            $headers = @{
                "Authorization" = "Bearer $token"
            }
            
            $response = Invoke-RestMethod -Uri "http://127.0.0.1:8765/status" -Method GET -Headers $headers -TimeoutSec 5 -ErrorAction SilentlyContinue
            
            if ($response) {
                Write-Host "Managed Processes:" -ForegroundColor Cyan
                Write-Host "==================" -ForegroundColor Cyan
                
                foreach ($proc in $response.processes.PSObject.Properties) {
                    $info = $proc.Value
                    $stateColor = switch ($info.state) {
                        'running' { 'Green' }
                        'stopped' { 'Red' }
                        'failed' { 'Red' }
                        'backoff' { 'Yellow' }
                        default { 'Gray' }
                    }
                    
                    Write-Host "  $($info.name): " -NoNewline -ForegroundColor Gray
                    Write-Host $info.state.ToUpper() -ForegroundColor $stateColor
                    
                    if ($info.pid) {
                        Write-Host "    PID: $($info.pid)" -ForegroundColor Gray
                    }
                    if ($info.restart_count -gt 0) {
                        Write-Host "    Restarts: $($info.restart_count)" -ForegroundColor Yellow
                    }
                }
            }
        }
    }
    catch {
        Write-Host "Could not retrieve managed process status" -ForegroundColor Yellow
    }
    
    Write-Host ""
    Write-Host "Management Commands:" -ForegroundColor Cyan
    Write-Host "  Start:     .\tools\start.ps1" -ForegroundColor Gray
    Write-Host "  Stop:      .\tools\stop.ps1" -ForegroundColor Gray
    Write-Host "  Restart:   .\tools\restart.ps1" -ForegroundColor Gray
    Write-Host "  Logs:      Get-Content logs\supervisor.log -Tail 50" -ForegroundColor Gray
    Write-Host ""
    
    exit 0
}
catch {
    Write-Msg "Error: $_" "ERROR"
    exit 1
}
