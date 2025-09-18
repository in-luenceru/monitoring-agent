# Windows Monitoring Agent Watchdog Script
# Monitors agent processes and restarts them if they fail
# Copyright (C) 2025, Monitoring Solutions Inc.

param(
    [string]$Action = "monitor"
)

# Configuration
$script:AGENT_HOME = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$script:CONFIG_FILE = Join-Path $script:AGENT_HOME "etc\ossec.conf"
$script:CLIENT_KEYS = Join-Path $script:AGENT_HOME "etc\client.keys"
$script:LOG_FILE = Join-Path $script:AGENT_HOME "logs\monitoring-watchdog.log"
$script:PID_DIR = Join-Path $script:AGENT_HOME "var\run"
$script:STATE_DIR = Join-Path $script:AGENT_HOME "var\state"

# Processes to monitor (Windows specific)
$script:MONITORED_PROCESSES = @("wazuh-agentd", "wazuh-execd")

# Configuration
$script:CHECK_INTERVAL = 30  # seconds between checks
$script:MAX_RESTART_ATTEMPTS = 5  # per process per hour
$script:RESTART_WINDOW = 3600  # 1 hour in seconds

# Ensure log directory exists
$logDir = Split-Path $script:LOG_FILE -Parent
if (-not (Test-Path $logDir)) {
    New-Item -Path $logDir -ItemType Directory -Force | Out-Null
}

function Write-WatchdogLog {
    param(
        [string]$Level,
        [string]$Message
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [WATCHDOG] [$Level] $Message"
    
    try {
        Add-Content -Path $script:LOG_FILE -Value $logEntry -ErrorAction Stop
    }
    catch {
        # Fallback to console
        Write-Host $logEntry
    }
}

function Test-ProcessRunning {
    param([string]$ProcessName)
    
    # Check if process is running by looking for binary
    $binaryName = $ProcessName
    if (-not $binaryName.EndsWith(".exe")) {
        $binaryName += ".exe"
    }
    
    $processes = Get-Process -Name $ProcessName.Replace(".exe", "") -ErrorAction SilentlyContinue
    return $processes.Count -gt 0
}

function Get-RestartCount {
    param([string]$ProcessName)
    
    $counterFile = Join-Path $script:STATE_DIR "restart_count_$ProcessName"
    if (Test-Path $counterFile) {
        try {
            return [int](Get-Content $counterFile -ErrorAction Stop)
        }
        catch {
            return 0
        }
    }
    return 0
}

function Set-RestartCount {
    param(
        [string]$ProcessName,
        [int]$Count
    )
    
    if (-not (Test-Path $script:STATE_DIR)) {
        New-Item -Path $script:STATE_DIR -ItemType Directory -Force | Out-Null
    }
    
    $counterFile = Join-Path $script:STATE_DIR "restart_count_$ProcessName"
    try {
        $Count | Set-Content -Path $counterFile -Encoding ASCII
    }
    catch {
        Write-WatchdogLog "WARN" "Failed to update restart counter for $ProcessName"
    }
}

function Get-LastRestartTime {
    param([string]$ProcessName)
    
    $timeFile = Join-Path $script:STATE_DIR "last_restart_$ProcessName"
    if (Test-Path $timeFile) {
        try {
            $timeString = Get-Content $timeFile -ErrorAction Stop
            return [DateTime]::ParseExact($timeString, "yyyy-MM-dd HH:mm:ss", $null)
        }
        catch {
            return [DateTime]::MinValue
        }
    }
    return [DateTime]::MinValue
}

function Set-LastRestartTime {
    param(
        [string]$ProcessName,
        [DateTime]$Time
    )
    
    if (-not (Test-Path $script:STATE_DIR)) {
        New-Item -Path $script:STATE_DIR -ItemType Directory -Force | Out-Null
    }
    
    $timeFile = Join-Path $script:STATE_DIR "last_restart_$ProcessName"
    try {
        $Time.ToString("yyyy-MM-dd HH:mm:ss") | Set-Content -Path $timeFile -Encoding ASCII
    }
    catch {
        Write-WatchdogLog "WARN" "Failed to update restart time for $ProcessName"
    }
}

function Test-ShouldRestart {
    param([string]$ProcessName)
    
    $currentTime = Get-Date
    $lastRestart = Get-LastRestartTime $ProcessName
    $restartCount = Get-RestartCount $ProcessName
    
    # Reset counter if restart window has passed
    if (($currentTime - $lastRestart).TotalSeconds -gt $script:RESTART_WINDOW) {
        Set-RestartCount $ProcessName 0
        $restartCount = 0
    }
    
    # Check if we've exceeded maximum restart attempts
    if ($restartCount -ge $script:MAX_RESTART_ATTEMPTS) {
        Write-WatchdogLog "ERROR" "Process $ProcessName has exceeded maximum restart attempts ($script:MAX_RESTART_ATTEMPTS) within the last hour"
        return $false
    }
    
    return $true
}

function Restart-MonitoredProcess {
    param([string]$ProcessName)
    
    Write-WatchdogLog "INFO" "Attempting to restart process: $ProcessName"
    
    # Check if we should restart
    if (-not (Test-ShouldRestart $ProcessName)) {
        return $false
    }
    
    # Call the main control script to restart the specific process
    $controlScript = Join-Path $script:AGENT_HOME "monitoring-agent-control.ps1"
    
    if (Test-Path $controlScript) {
        try {
            $result = & $controlScript "restart-process" $ProcessName
            
            # Update restart tracking
            $currentTime = Get-Date
            Set-LastRestartTime $ProcessName $currentTime
            
            $restartCount = Get-RestartCount $ProcessName
            Set-RestartCount $ProcessName ($restartCount + 1)
            
            Write-WatchdogLog "INFO" "Successfully restarted $ProcessName (restart count: $($restartCount + 1))"
            return $true
        }
        catch {
            Write-WatchdogLog "ERROR" "Failed to restart $ProcessName`: $($_.Exception.Message)"
            return $false
        }
    }
    else {
        Write-WatchdogLog "ERROR" "Control script not found: $controlScript"
        return $false
    }
}

function Test-AgentShouldBeRunning {
    # Check if the agent is supposed to be running
    $stateFile = Join-Path $script:STATE_DIR "was_running"
    
    # If state file doesn't exist, assume agent should be running if client.keys exists
    if (-not (Test-Path $stateFile)) {
        return (Test-Path $script:CLIENT_KEYS)
    }
    
    try {
        $state = Get-Content $stateFile -ErrorAction Stop
        return $state -eq "true"
    }
    catch {
        return $false
    }
}

function Start-WatchdogMonitoring {
    Write-WatchdogLog "INFO" "Starting Windows Monitoring Agent Watchdog"
    Write-WatchdogLog "INFO" "Monitoring processes: $($script:MONITORED_PROCESSES -join ', ')"
    Write-WatchdogLog "INFO" "Check interval: $script:CHECK_INTERVAL seconds"
    Write-WatchdogLog "INFO" "Max restarts per hour: $script:MAX_RESTART_ATTEMPTS"
    
    $lastHealthReport = Get-Date
    $healthReportInterval = 300  # 5 minutes
    
    while ($true) {
        try {
            # Check if agent should be running
            if (-not (Test-AgentShouldBeRunning)) {
                Write-WatchdogLog "DEBUG" "Agent is not supposed to be running, watchdog sleeping..."
                Start-Sleep -Seconds $script:CHECK_INTERVAL
                continue
            }
            
            # Monitor each process
            foreach ($processName in $script:MONITORED_PROCESSES) {
                if (-not (Test-ProcessRunning $processName)) {
                    Write-WatchdogLog "WARN" "Process $processName is not running"
                    
                    # Attempt restart
                    $restartSuccess = Restart-MonitoredProcess $processName
                    if ($restartSuccess) {
                        Write-WatchdogLog "INFO" "Successfully restarted $processName"
                    }
                    else {
                        Write-WatchdogLog "ERROR" "Failed to restart $processName"
                    }
                }
                else {
                    Write-WatchdogLog "DEBUG" "Process $processName is running normally"
                }
            }
            
            # Periodic health report
            $now = Get-Date
            if (($now - $lastHealthReport).TotalSeconds -gt $healthReportInterval) {
                $runningCount = 0
                foreach ($processName in $script:MONITORED_PROCESSES) {
                    if (Test-ProcessRunning $processName) {
                        $runningCount++
                    }
                }
                Write-WatchdogLog "INFO" "Health report: $runningCount/$($script:MONITORED_PROCESSES.Count) processes running"
                $lastHealthReport = $now
            }
            
            # Sleep until next check
            Start-Sleep -Seconds $script:CHECK_INTERVAL
        }
        catch {
            Write-WatchdogLog "ERROR" "Watchdog error: $($_.Exception.Message)"
            Start-Sleep -Seconds $script:CHECK_INTERVAL
        }
    }
}

function Stop-WatchdogMonitoring {
    Write-WatchdogLog "INFO" "Stopping Windows Monitoring Agent Watchdog"
    exit 0
}

# Handle Ctrl+C gracefully
$null = Register-ObjectEvent -InputObject ([Console]) -EventName CancelKeyPress -Action {
    Write-WatchdogLog "INFO" "Watchdog received stop signal"
    Stop-WatchdogMonitoring
}

# Main execution
switch ($Action.ToLower()) {
    "monitor" {
        Start-WatchdogMonitoring
    }
    "stop" {
        Stop-WatchdogMonitoring
    }
    default {
        Write-Host "Usage: monitoring-watchdog.ps1 [monitor|stop]"
        exit 1
    }
}