# Persistent Agent Monitor
# This script keeps the monitoring agent running continuously

param(
    [switch]$Stop
)

$BinPath = "c:\Users\ANANDHU\OneDrive\Desktop\monitoring-agent\windows\bin"
$LogFile = "c:\Users\ANANDHU\OneDrive\Desktop\monitoring-agent\agent-monitor.log"

function Write-MonitorLog {
    param($Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp - $Message" | Out-File -FilePath $LogFile -Append
    Write-Host "$timestamp - $Message"
}

if ($Stop) {
    Write-MonitorLog "Stopping agent monitor..."
    Get-Process -Name "MONITORING_AGENT" -ErrorAction SilentlyContinue | Stop-Process -Force
    exit
}

Write-MonitorLog "Starting persistent agent monitor..."

while ($true) {
    # Check if agent is running
    $agentProcess = Get-Process -Name "MONITORING_AGENT" -ErrorAction SilentlyContinue
    
    if (-not $agentProcess) {
        Write-MonitorLog "Agent not running, starting..."
        try {
            Push-Location $BinPath
            $newProcess = Start-Process -FilePath "MONITORING_AGENT.EXE" -ArgumentList "start" -WindowStyle Hidden -PassThru
            Write-MonitorLog "Started agent with PID: $($newProcess.Id)"
            Pop-Location
        } catch {
            Write-MonitorLog "Failed to start agent: $($_.Exception.Message)"
            Pop-Location
        }
    } else {
        Write-MonitorLog "Agent running with PID: $($agentProcess.Id)"
    }
    
    # Wait 30 seconds before checking again
    Start-Sleep 30
}