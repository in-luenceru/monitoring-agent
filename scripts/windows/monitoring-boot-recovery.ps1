# Windows Monitoring Agent Boot Recovery Script
# Handles automatic recovery after system reboots and failures
# Copyright (C) 2025, Monitoring Solutions Inc.

param(
    [string]$Action = "check"
)

# Configuration
$script:AGENT_HOME = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$script:STATE_DIR = Join-Path $script:AGENT_HOME "var\state"
$script:LOG_FILE = Join-Path $script:AGENT_HOME "logs\boot-recovery.log"
$script:CONFIG_FILE = Join-Path $script:AGENT_HOME "etc\ossec.conf"
$script:CLIENT_KEYS = Join-Path $script:AGENT_HOME "etc\client.keys"
$script:CONTROL_SCRIPT = Join-Path $script:AGENT_HOME "monitoring-agent-control.ps1"

# State files
$script:WAS_RUNNING_FILE = Join-Path $script:STATE_DIR "was_running"
$script:STARTUP_TIME_FILE = Join-Path $script:STATE_DIR "startup_time"
$script:RECOVERY_LOG = Join-Path $script:AGENT_HOME "logs\boot-recovery.log"

# Ensure required directories exist
$requiredDirs = @($script:STATE_DIR, (Split-Path $script:LOG_FILE -Parent))
foreach ($dir in $requiredDirs) {
    if (-not (Test-Path $dir)) {
        New-Item -Path $dir -ItemType Directory -Force | Out-Null
    }
}

function Write-RecoveryLog {
    param(
        [string]$Level,
        [string]$Message
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [RECOVERY] [$Level] $Message"
    
    try {
        Add-Content -Path $script:LOG_FILE -Value $logEntry -ErrorAction Stop
    }
    catch {
        # Fallback to console
        Write-Host $logEntry
    }
}

function Test-AgentWasRunning {
    # Check if agent was running before shutdown/reboot
    if (Test-Path $script:WAS_RUNNING_FILE) {
        try {
            $state = Get-Content $script:WAS_RUNNING_FILE -ErrorAction Stop
            return $state -eq "true"
        }
        catch {
            return $false
        }
    }
    
    # If no state file exists, check if agent is enrolled (has client.keys)
    return (Test-Path $script:CLIENT_KEYS)
}

function Set-AgentRunningState {
    param([bool]$IsRunning)
    
    if (-not (Test-Path $script:STATE_DIR)) {
        New-Item -Path $script:STATE_DIR -ItemType Directory -Force | Out-Null
    }
    
    try {
        $state = if ($IsRunning) { "true" } else { "false" }
        $state | Set-Content -Path $script:WAS_RUNNING_FILE -Encoding ASCII
        Write-RecoveryLog "DEBUG" "Set agent running state to: $state"
    }
    catch {
        Write-RecoveryLog "WARN" "Failed to set running state: $($_.Exception.Message)"
    }
}

function Test-AgentCurrentlyRunning {
    # Check if monitoring agent processes are currently running
    $monitoringProcesses = @("wazuh-agentd", "wazuh-execd")
    
    foreach ($processName in $monitoringProcesses) {
        $processes = Get-Process -Name $processName.Replace(".exe", "") -ErrorAction SilentlyContinue
        if ($processes.Count -gt 0) {
            return $true
        }
    }
    
    return $false
}

function Get-SystemBootTime {
    try {
        $bootTime = (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime
        return $bootTime
    }
    catch {
        Write-RecoveryLog "WARN" "Failed to get system boot time: $($_.Exception.Message)"
        return [DateTime]::MinValue
    }
}

function Get-LastAgentStartupTime {
    if (Test-Path $script:STARTUP_TIME_FILE) {
        try {
            $timestamp = Get-Content $script:STARTUP_TIME_FILE -ErrorAction Stop
            # Convert Unix timestamp to DateTime
            $epochStart = [DateTime]"1970-01-01 00:00:00"
            return $epochStart.AddSeconds([int]$timestamp)
        }
        catch {
            Write-RecoveryLog "WARN" "Failed to parse startup time: $($_.Exception.Message)"
            return [DateTime]::MinValue
        }
    }
    return [DateTime]::MinValue
}

function Test-NeedsRecovery {
    $bootTime = Get-SystemBootTime
    $lastStartup = Get-LastAgentStartupTime
    
    # If system booted after last agent startup, we might need recovery
    if ($bootTime -gt $lastStartup) {
        Write-RecoveryLog "INFO" "System boot time ($bootTime) is after last agent startup ($lastStartup)"
        return $true
    }
    
    return $false
}

function Start-RecoveryProcess {
    Write-RecoveryLog "INFO" "Starting agent recovery process..."
    
    # Check if agent should be running
    if (-not (Test-AgentWasRunning)) {
        Write-RecoveryLog "INFO" "Agent was not running before shutdown - no recovery needed"
        return $true
    }
    
    # Check if agent is already running
    if (Test-AgentCurrentlyRunning) {
        Write-RecoveryLog "INFO" "Agent is already running - no recovery needed"
        Set-AgentRunningState $true
        return $true
    }
    
    # Check if we need to recover due to system reboot
    if (-not (Test-NeedsRecovery)) {
        Write-RecoveryLog "DEBUG" "No recovery needed based on boot time analysis"
        return $true
    }
    
    Write-RecoveryLog "INFO" "Attempting to recover monitoring agent..."
    
    # Verify configuration exists
    if (-not (Test-Path $script:CONFIG_FILE)) {
        Write-RecoveryLog "ERROR" "Configuration file not found: $script:CONFIG_FILE"
        return $false
    }
    
    if (-not (Test-Path $script:CLIENT_KEYS)) {
        Write-RecoveryLog "ERROR" "Client keys file not found: $script:CLIENT_KEYS"
        return $false
    }
    
    # Attempt to start the agent
    if (Test-Path $script:CONTROL_SCRIPT) {
        try {
            Write-RecoveryLog "INFO" "Starting monitoring agent..."
            
            # Start the agent using the control script
            $startResult = & $script:CONTROL_SCRIPT "start"
            
            # Give it time to start
            Start-Sleep -Seconds 5
            
            # Verify it's running
            if (Test-AgentCurrentlyRunning) {
                Write-RecoveryLog "INFO" "✅ Agent recovery successful - monitoring agent is now running"
                Set-AgentRunningState $true
                return $true
            }
            else {
                Write-RecoveryLog "ERROR" "❌ Agent recovery failed - agent is not running after start attempt"
                return $false
            }
        }
        catch {
            Write-RecoveryLog "ERROR" "Failed to start agent: $($_.Exception.Message)"
            return $false
        }
    }
    else {
        Write-RecoveryLog "ERROR" "Control script not found: $script:CONTROL_SCRIPT"
        return $false
    }
}

function Test-RecoveryHealth {
    Write-RecoveryLog "INFO" "Performing recovery health check..."
    
    $healthIssues = 0
    
    # Check if agent should be running
    $shouldBeRunning = Test-AgentWasRunning
    $isRunning = Test-AgentCurrentlyRunning
    
    Write-RecoveryLog "INFO" "Agent state - Should be running: $shouldBeRunning, Is running: $isRunning"
    
    if ($shouldBeRunning -and -not $isRunning) {
        Write-RecoveryLog "ERROR" "❌ Agent should be running but is not"
        $healthIssues++
    }
    elseif (-not $shouldBeRunning -and $isRunning) {
        Write-RecoveryLog "WARN" "⚠ Agent is running but was marked as stopped"
    }
    elseif ($shouldBeRunning -and $isRunning) {
        Write-RecoveryLog "INFO" "✅ Agent is running as expected"
    }
    else {
        Write-RecoveryLog "INFO" "ℹ Agent is stopped as expected"
    }
    
    # Check configuration files
    if (-not (Test-Path $script:CONFIG_FILE)) {
        Write-RecoveryLog "ERROR" "❌ Configuration file missing: $script:CONFIG_FILE"
        $healthIssues++
    }
    else {
        Write-RecoveryLog "INFO" "✅ Configuration file exists"
    }
    
    if ($shouldBeRunning -and -not (Test-Path $script:CLIENT_KEYS)) {
        Write-RecoveryLog "ERROR" "❌ Client keys file missing: $script:CLIENT_KEYS"
        $healthIssues++
    }
    elseif (Test-Path $script:CLIENT_KEYS) {
        Write-RecoveryLog "INFO" "✅ Client keys file exists"
    }
    
    # Check boot time vs startup time
    $needsRecovery = Test-NeedsRecovery
    if ($needsRecovery -and $shouldBeRunning -and -not $isRunning) {
        Write-RecoveryLog "WARN" "⚠ System appears to have rebooted since last agent startup"
    }
    
    if ($healthIssues -eq 0) {
        Write-RecoveryLog "INFO" "✅ Recovery health check passed"
        return $true
    }
    else {
        Write-RecoveryLog "ERROR" "❌ Recovery health check failed with $healthIssues issues"
        return $false
    }
}

function Mark-AgentRunning {
    Set-AgentRunningState $true
    Write-RecoveryLog "INFO" "Marked agent as running"
}

function Mark-AgentStopped {
    Set-AgentRunningState $false
    Write-RecoveryLog "INFO" "Marked agent as stopped"
}

# Main execution
switch ($Action.ToLower()) {
    "check" {
        Write-RecoveryLog "INFO" "Starting boot recovery check..."
        $recoveryResult = Start-RecoveryProcess
        if ($recoveryResult) {
            Write-RecoveryLog "INFO" "Boot recovery check completed successfully"
            exit 0
        }
        else {
            Write-RecoveryLog "ERROR" "Boot recovery check failed"
            exit 1
        }
    }
    "health" {
        $healthResult = Test-RecoveryHealth
        if ($healthResult) {
            exit 0
        }
        else {
            exit 1
        }
    }
    "mark-running" {
        Mark-AgentRunning
    }
    "mark-stopped" {
        Mark-AgentStopped
    }
    "status" {
        $wasRunning = Test-AgentWasRunning
        $isRunning = Test-AgentCurrentlyRunning
        $needsRecovery = Test-NeedsRecovery
        
        Write-RecoveryLog "INFO" "Recovery Status:"
        Write-RecoveryLog "INFO" "  Was running: $wasRunning"
        Write-RecoveryLog "INFO" "  Is running: $isRunning"
        Write-RecoveryLog "INFO" "  Needs recovery: $needsRecovery"
    }
    default {
        Write-Host "Usage: monitoring-boot-recovery.ps1 [check|health|mark-running|mark-stopped|status]"
        exit 1
    }
}