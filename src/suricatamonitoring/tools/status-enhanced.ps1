#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Check RiskNoX Supervisor Service Status
    
.DESCRIPTION
    Displays comprehensive status information for the RiskNoX Supervisor Service
    and all managed processes. Queries the Control API for detailed state information.
    Shows enrollment status, port checks, and process details.
    
.PARAMETER Detailed
    Show detailed information including PIDs, uptime, resource usage, and logs
    
.EXAMPLE
    .\status.ps1
    .\status.ps1 -Detailed
    
.NOTES
    Requires the supervisor service to be running for full status
#>

param(
    [switch]$Detailed
)

$ServiceName = "RiskNoXSupervisor"
$ControlApiUrl = "http://127.0.0.1:8765"
$AgentRoot = Split-Path $PSScriptRoot -Parent
$TokenFile = Join-Path $AgentRoot "config\supervisor_token.txt"
$ClientKeys = Join-Path $AgentRoot "client.keys"
$OssecConf = Join-Path $AgentRoot "ossec.conf"

# Color functions
function Write-Info { param([string]$msg) Write-Host $msg -ForegroundColor Cyan }
function Write-Success { param([string]$msg) Write-Host $msg -ForegroundColor Green }
function Write-Warning { param([string]$msg) Write-Host $msg -ForegroundColor Yellow }
function Write-ErrorMsg { param([string]$msg) Write-Host $msg -ForegroundColor Red }

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  RiskNoX Supervisor Status" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check if service exists
$service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if (-not $service) {
    Write-ErrorMsg "Service '$ServiceName' not found"
    Write-Info "Install the service first: .\install_service.ps1"
    exit 1
}

# Display service status
Write-Info "Windows Service Status:"
$serviceColor = if ($service.Status -eq 'Running') { 'Green' } else { 'Red' }
Write-Host "  Service Name:   $ServiceName" -ForegroundColor Gray
Write-Host "  Status:         " -NoNewline
Write-Host $service.Status -ForegroundColor $serviceColor
Write-Host "  Start Type:     $($service.StartType)" -ForegroundColor Gray
Write-Host ""

if ($service.Status -ne 'Running') {
    Write-Warning "Service is not running. Start it with: .\start.ps1"
    
    # Show enrollment status even when stopped
    if (Test-Path $ClientKeys) {
        Write-Host ""
        Write-Info "Agent Enrollment Status:"
        Write-Success "  ✓ Client keys present"
    } else {
        Write-Host ""
        Write-Warning "Agent Enrollment Status:"
        Write-Warning "  ✗ Client keys not found"
        Write-Info "    Enroll agent: .\tools\enroll-agent.ps1 -Interactive"
    }
    
    exit 0
}

# Check port 5000 (backend server)
Write-Info "Port Status:"
try {
    $tcpConnection = Test-NetConnection -ComputerName 127.0.0.1 -Port 5000 -WarningAction SilentlyContinue -InformationLevel Quiet
    if ($tcpConnection) {
        Write-Success "  ✓ Backend API (port 5000): LISTENING"
    } else {
        Write-Warning "  ✗ Backend API (port 5000): NOT LISTENING"
    }
}
catch {
    Write-Warning "  ? Backend API (port 5000): UNKNOWN"
}
Write-Host ""

# Check agent enrollment
Write-Info "Agent Enrollment:"
if (Test-Path $ClientKeys) {
    try {
        $keyContent = Get-Content $ClientKeys -Raw
        if ($keyContent.Trim().Length -gt 0) {
            Write-Success "  ✓ Client keys configured"
            
            # Parse manager IP from ossec.conf
            if (Test-Path $OssecConf) {
                [xml]$ossecXml = Get-Content $OssecConf
                $managerIP = $ossecXml.ossec_config.client.server.address
                if ($managerIP) {
                    Write-Info "    Manager IP: $managerIP"
                }
            }
        } else {
            Write-Warning "  ✗ Client keys file is empty"
            Write-Info "    Enroll agent: .\tools\enroll-agent.ps1 -Interactive"
        }
    }
    catch {
        Write-Warning "  ? Client keys unreadable"
    }
} else {
    Write-Warning "  ✗ Client keys not found"
    Write-Info "    Enroll agent: .\tools\enroll-agent.ps1 -Interactive"
}
Write-Host ""

# Try to query Control API
Write-Info "Querying Control API..."
try {
    # Read authentication token
    if (!(Test-Path $TokenFile)) {
        Write-Warning "Token file not found: $TokenFile"
        Write-Info "API status check unavailable"
        exit 0
    }
    
    $token = Get-Content $TokenFile -Raw | ForEach-Object { $_.Trim() }
    $headers = @{
        "Authorization" = "Bearer $token"
    }
    
    # Query status endpoint
    $response = Invoke-RestMethod -Uri "$ControlApiUrl/status" -Method GET -Headers $headers -TimeoutSec 5
    
    Write-Host ""
    Write-Info "Managed Processes:"
    Write-Host ""
    
    if ($response -and $response.processes) {
        foreach ($process in $response.processes) {
            $stateName = $process.state
            $stateColor = switch ($stateName) {
                "running" { "Green" }
                "starting" { "Yellow" }
                "stopping" { "Yellow" }
                "backoff" { "Yellow" }
                "failed" { "Red" }
                "stopped" { "Gray" }
                default { "White" }
            }
            
            Write-Host "  $($process.name):" -ForegroundColor White
            Write-Host "    State:          " -NoNewline
            Write-Host $stateName.ToUpper() -ForegroundColor $stateColor
            
            if ($process.pid -and $process.pid -gt 0) {
                Write-Host "    PID:            $($process.pid)" -ForegroundColor Gray
                
                # Get additional process details
                try {
                    $proc = Get-Process -Id $process.pid -ErrorAction SilentlyContinue
                    if ($proc) {
                        # Show uptime
                        $uptime = (Get-Date) - $proc.StartTime
                        $uptimeStr = if ($uptime.TotalDays -ge 1) {
                            "$([int]$uptime.TotalDays)d $($uptime.Hours)h $($uptime.Minutes)m"
                        } elseif ($uptime.TotalHours -ge 1) {
                            "$($uptime.Hours)h $($uptime.Minutes)m $($uptime.Seconds)s"
                        } else {
                            "$($uptime.Minutes)m $($uptime.Seconds)s"
                        }
                        Write-Host "    Uptime:         $uptimeStr" -ForegroundColor Gray
                        
                        if ($Detailed) {
                            Write-Host "    CPU:            $([math]::Round($proc.CPU, 2))s" -ForegroundColor Gray
                            Write-Host "    Memory:         $([math]::Round($proc.WorkingSet64 / 1MB, 2)) MB" -ForegroundColor Gray
                            Write-Host "    Threads:        $($proc.Threads.Count)" -ForegroundColor Gray
                            
                            # Show command line (truncated)
                            try {
                                $cmdLine = (Get-CimInstance -ClassName Win32_Process -Filter "ProcessId = $($process.pid)" -ErrorAction SilentlyContinue).CommandLine
                                if ($cmdLine -and $cmdLine.Length -gt 0) {
                                    $cmdShort = if ($cmdLine.Length -gt 80) { $cmdLine.Substring(0, 77) + "..." } else { $cmdLine }
                                    Write-Host "    Command:        $cmdShort" -ForegroundColor DarkGray
                                }
                            }
                            catch { }
                        }
                    }
                }
                catch {
                    # Process might have exited
                }
            }
            
            if ($process.restart_count -ne $null) {
                $restartColor = if ($process.restart_count -gt 0) { "Yellow" } else { "Gray" }
                Write-Host "    Restarts:       $($process.restart_count)" -ForegroundColor $restartColor
            }
            
            Write-Host ""
        }
        
        # Summary statistics
        $runningCount = ($response.processes | Where-Object { $_.state -eq "running" }).Count
        $totalCount = $response.processes.Count
        $failedCount = ($response.processes | Where-Object { $_.state -eq "failed" }).Count
        
        Write-Host "  Summary:" -ForegroundColor White
        Write-Host "    Total Processes:  $totalCount" -ForegroundColor Gray
        Write-Host "    Running:          " -NoNewline
        if ($runningCount -eq $totalCount) {
            Write-Host "$runningCount" -ForegroundColor Green
        } else {
            Write-Host "$runningCount" -ForegroundColor Yellow
        }
        if ($failedCount -gt 0) {
            Write-Host "    Failed:           $failedCount" -ForegroundColor Red
        }
        Write-Host ""
        
    } else {
        Write-Warning "No processes reported by supervisor"
    }
    
    # Show log locations if detailed
    if ($Detailed) {
        Write-Host ""
        Write-Info "Log Files:"
        $logDir = Join-Path $AgentRoot "logs"
        if (Test-Path $logDir) {
            $logs = @(
                "supervisor.log",
                "backend_server_stdout.log",
                "backend_server_stderr.log",
                "agent_poll_stdout.log",
                "agent_poll_stderr.log",
                "monitoring_agent_stdout.log",
                "monitoring_agent_stderr.log",
                "suricata_ids_stdout.log",
                "suricata_ids_stderr.log"
            )
            
            foreach ($log in $logs) {
                $logPath = Join-Path $logDir $log
                if (Test-Path $logPath) {
                    $logInfo = Get-Item $logPath
                    $sizeKB = [math]::Round($logInfo.Length / 1KB, 1)
                    Write-Host "    $log" -NoNewline -ForegroundColor Gray
                    Write-Host " ($sizeKB KB)" -ForegroundColor DarkGray
                }
            }
        }
        Write-Host ""
        Write-Info "View logs:"
        Write-Info "  Get-Content $logDir\supervisor.log -Tail 50 -Wait"
        Write-Info "  Get-Content $logDir\backend_server_stderr.log -Tail 50"
    }
    
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Success "✓ Status check complete"
    Write-Host ""
    
    if ($runningCount -eq $totalCount -and $failedCount -eq 0) {
        Write-Success "All systems operational! 🚀"
    } elseif ($failedCount -gt 0) {
        Write-ErrorMsg "Some processes have failed!"
        Write-Info "Check logs: Get-Content logs\supervisor.log -Tail 100"
        Write-Info "Restart failed: .\tools\restart.ps1"
    } else {
        Write-Warning "Some processes are not running"
        Write-Info "Wait for startup or check logs"
    }
}
catch {
    Write-Warning "Failed to query Control API: $($_.Exception.Message)"
    Write-Info "Service is running but API is not responding"
    Write-Info "Check supervisor logs: Get-Content logs\supervisor.log -Tail 100"
}
