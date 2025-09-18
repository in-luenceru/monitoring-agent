# Windows Monitoring Agent Recovery Monitoring Script
# Continuously monitors agent health and performs recovery actions
# Copyright (C) 2025, Monitoring Solutions Inc.

param(
    [string]$Action = "monitor"
)

# Configuration
$script:AGENT_HOME = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$script:LOG_FILE = Join-Path $script:AGENT_HOME "logs\monitoring-recovery.log"
$script:STATE_DIR = Join-Path $script:AGENT_HOME "var\state"
$script:CONTROL_SCRIPT = Join-Path $script:AGENT_HOME "monitoring-agent-control.ps1"

# Monitoring configuration
$script:CHECK_INTERVAL = 60  # seconds between health checks
$script:RECOVERY_TIMEOUT = 300  # 5 minutes timeout for recovery actions
$script:MAX_RECOVERY_ATTEMPTS = 3  # max recovery attempts per issue

# Ensure log directory exists
$logDir = Split-Path $script:LOG_FILE -Parent
if (-not (Test-Path $logDir)) {
    New-Item -Path $logDir -ItemType Directory -Force | Out-Null
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

function Test-AgentProcesses {
    # Check if all required monitoring processes are running
    $requiredProcesses = @("wazuh-agentd", "wazuh-execd")
    $runningProcesses = @()
    $missingProcesses = @()
    
    foreach ($processName in $requiredProcesses) {
        $processes = Get-Process -Name $processName.Replace(".exe", "") -ErrorAction SilentlyContinue
        if ($processes.Count -gt 0) {
            $runningProcesses += $processName
        }
        else {
            $missingProcesses += $processName
        }
    }
    
    return @{
        Running = $runningProcesses
        Missing = $missingProcesses
        AllRunning = $missingProcesses.Count -eq 0
    }
}

function Test-AgentConnectivity {
    # Test if agent can communicate with manager
    # This is a basic check - in reality you might want to check logs or use agent tools
    
    $clientKeysFile = Join-Path $script:AGENT_HOME "etc\client.keys"
    $configFile = Join-Path $script:AGENT_HOME "etc\ossec.conf"
    
    # Basic checks
    if (-not (Test-Path $clientKeysFile)) {
        return @{
            Connected = $false
            Issue = "Client keys file missing"
        }
    }
    
    if (-not (Test-Path $configFile)) {
        return @{
            Connected = $false
            Issue = "Configuration file missing"
        }
    }
    
    # Check if agent processes are running (basic connectivity indicator)
    $processStatus = Test-AgentProcesses
    if (-not $processStatus.AllRunning) {
        return @{
            Connected = $false
            Issue = "Agent processes not running"
        }
    }
    
    # If we get here, basic connectivity appears OK
    return @{
        Connected = $true
        Issue = $null
    }
}

function Test-AgentConfiguration {
    # Validate agent configuration
    $configFile = Join-Path $script:AGENT_HOME "etc\ossec.conf"
    
    if (-not (Test-Path $configFile)) {
        return @{
            Valid = $false
            Issue = "Configuration file missing"
        }
    }
    
    try {
        $configContent = Get-Content $configFile -Raw -ErrorAction Stop
        
        # Basic XML structure check
        if ($configContent -notmatch '<ossec_config>' -or $configContent -notmatch '</ossec_config>') {
            return @{
                Valid = $false
                Issue = "Invalid XML structure"
            }
        }
        
        # Check for required sections
        if ($configContent -notmatch '<client>') {
            return @{
                Valid = $false
                Issue = "Missing client section"
            }
        }
        
        if ($configContent -notmatch '<server>') {
            return @{
                Valid = $false
                Issue = "Missing server section"
            }
        }
        
        return @{
            Valid = $true
            Issue = $null
        }
    }
    catch {
        return @{
            Valid = $false
            Issue = "Failed to read configuration: $($_.Exception.Message)"
        }
    }
}

function Get-RecoveryAttemptCount {
    param([string]$IssueType)
    
    $counterFile = Join-Path $script:STATE_DIR "recovery_attempts_$IssueType"
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

function Set-RecoveryAttemptCount {
    param(
        [string]$IssueType,
        [int]$Count
    )
    
    if (-not (Test-Path $script:STATE_DIR)) {
        New-Item -Path $script:STATE_DIR -ItemType Directory -Force | Out-Null
    }
    
    $counterFile = Join-Path $script:STATE_DIR "recovery_attempts_$IssueType"
    try {
        $Count | Set-Content -Path $counterFile -Encoding ASCII
    }
    catch {
        Write-RecoveryLog "WARN" "Failed to update recovery attempt counter for $IssueType"
    }
}

function Reset-RecoveryAttemptCounters {
    # Reset all recovery attempt counters (called when agent is healthy)
    if (Test-Path $script:STATE_DIR) {
        $counterFiles = Get-ChildItem -Path $script:STATE_DIR -Filter "recovery_attempts_*" -ErrorAction SilentlyContinue
        foreach ($file in $counterFiles) {
            try {
                Remove-Item $file.FullName -Force
            }
            catch {
                Write-RecoveryLog "WARN" "Failed to remove recovery counter: $($file.Name)"
            }
        }
    }
}

function Invoke-ProcessRecovery {
    param([array]$MissingProcesses)
    
    $issueType = "processes"
    $attemptCount = Get-RecoveryAttemptCount $issueType
    
    if ($attemptCount -ge $script:MAX_RECOVERY_ATTEMPTS) {
        Write-RecoveryLog "ERROR" "Maximum recovery attempts reached for process issues ($attemptCount)"
        return $false
    }
    
    Write-RecoveryLog "INFO" "Attempting process recovery (attempt $($attemptCount + 1))"
    Write-RecoveryLog "INFO" "Missing processes: $($MissingProcesses -join ', ')"
    
    try {
        # Try to restart the agent
        if (Test-Path $script:CONTROL_SCRIPT) {
            $result = & $script:CONTROL_SCRIPT "restart"
            
            # Wait for processes to start
            Start-Sleep -Seconds 10
            
            # Verify recovery
            $newStatus = Test-AgentProcesses
            if ($newStatus.AllRunning) {
                Write-RecoveryLog "INFO" "✅ Process recovery successful"
                Set-RecoveryAttemptCount $issueType 0  # Reset counter on success
                return $true
            }
            else {
                Write-RecoveryLog "ERROR" "❌ Process recovery failed - still missing: $($newStatus.Missing -join ', ')"
                Set-RecoveryAttemptCount $issueType ($attemptCount + 1)
                return $false
            }
        }
        else {
            Write-RecoveryLog "ERROR" "Control script not found: $script:CONTROL_SCRIPT"
            return $false
        }
    }
    catch {
        Write-RecoveryLog "ERROR" "Process recovery failed: $($_.Exception.Message)"
        Set-RecoveryAttemptCount $issueType ($attemptCount + 1)
        return $false
    }
}

function Invoke-ConnectivityRecovery {
    param([string]$Issue)
    
    $issueType = "connectivity"
    $attemptCount = Get-RecoveryAttemptCount $issueType
    
    if ($attemptCount -ge $script:MAX_RECOVERY_ATTEMPTS) {
        Write-RecoveryLog "ERROR" "Maximum recovery attempts reached for connectivity issues ($attemptCount)"
        return $false
    }
    
    Write-RecoveryLog "INFO" "Attempting connectivity recovery (attempt $($attemptCount + 1))"
    Write-RecoveryLog "INFO" "Issue: $Issue"
    
    try {
        if (Test-Path $script:CONTROL_SCRIPT) {
            $result = & $script:CONTROL_SCRIPT "restart"
            
            # Wait for connectivity to restore
            Start-Sleep -Seconds 15
            
            # Verify recovery
            $newStatus = Test-AgentConnectivity
            if ($newStatus.Connected) {
                Write-RecoveryLog "INFO" "✅ Connectivity recovery successful"
                Set-RecoveryAttemptCount $issueType 0  # Reset counter on success
                return $true
            }
            else {
                Write-RecoveryLog "ERROR" "❌ Connectivity recovery failed: $($newStatus.Issue)"
                Set-RecoveryAttemptCount $issueType ($attemptCount + 1)
                return $false
            }
        }
        else {
            Write-RecoveryLog "ERROR" "Control script not found: $script:CONTROL_SCRIPT"
            return $false
        }
    }
    catch {
        Write-RecoveryLog "ERROR" "Connectivity recovery failed: $($_.Exception.Message)"
        Set-RecoveryAttemptCount $issueType ($attemptCount + 1)
        return $false
    }
}

function Start-RecoveryMonitoring {
    Write-RecoveryLog "INFO" "Starting Windows Monitoring Agent Recovery Monitor"
    Write-RecoveryLog "INFO" "Check interval: $script:CHECK_INTERVAL seconds"
    Write-RecoveryLog "INFO" "Max recovery attempts: $script:MAX_RECOVERY_ATTEMPTS per issue type"
    
    $lastHealthReport = Get-Date
    $healthReportInterval = 300  # 5 minutes
    
    while ($true) {
        try {
            # Perform health checks
            $processStatus = Test-AgentProcesses
            $connectivityStatus = Test-AgentConnectivity
            $configStatus = Test-AgentConfiguration
            
            $issuesFound = $false
            
            # Check process status
            if (-not $processStatus.AllRunning) {
                Write-RecoveryLog "WARN" "Process issue detected - missing: $($processStatus.Missing -join ', ')"
                $recoveryResult = Invoke-ProcessRecovery $processStatus.Missing
                $issuesFound = $true
            }
            
            # Check connectivity
            if (-not $connectivityStatus.Connected) {
                Write-RecoveryLog "WARN" "Connectivity issue detected: $($connectivityStatus.Issue)"
                $recoveryResult = Invoke-ConnectivityRecovery $connectivityStatus.Issue
                $issuesFound = $true
            }
            
            # Check configuration
            if (-not $configStatus.Valid) {
                Write-RecoveryLog "ERROR" "Configuration issue detected: $($configStatus.Issue)"
                # Configuration issues typically require manual intervention
                $issuesFound = $true
            }
            
            # If no issues found, reset recovery counters
            if (-not $issuesFound) {
                Reset-RecoveryAttemptCounters
            }
            
            # Periodic health report
            $now = Get-Date
            if (($now - $lastHealthReport).TotalSeconds -gt $healthReportInterval) {
                $healthStatus = if (-not $issuesFound) { "HEALTHY" } else { "ISSUES_DETECTED" }
                Write-RecoveryLog "INFO" "Health report: $healthStatus - Processes: $($processStatus.Running.Count)/$($processStatus.Running.Count + $processStatus.Missing.Count) running"
                $lastHealthReport = $now
            }
            
            # Sleep until next check
            Start-Sleep -Seconds $script:CHECK_INTERVAL
        }
        catch {
            Write-RecoveryLog "ERROR" "Recovery monitor error: $($_.Exception.Message)"
            Start-Sleep -Seconds $script:CHECK_INTERVAL
        }
    }
}

function Stop-RecoveryMonitoring {
    Write-RecoveryLog "INFO" "Stopping Windows Monitoring Agent Recovery Monitor"
    exit 0
}

# Handle Ctrl+C gracefully
$null = Register-ObjectEvent -InputObject ([Console]) -EventName CancelKeyPress -Action {
    Write-RecoveryLog "INFO" "Recovery monitor received stop signal"
    Stop-RecoveryMonitoring
}

# Main execution
switch ($Action.ToLower()) {
    "monitor" {
        Start-RecoveryMonitoring
    }
    "stop" {
        Stop-RecoveryMonitoring
    }
    "health" {
        $processStatus = Test-AgentProcesses
        $connectivityStatus = Test-AgentConnectivity
        $configStatus = Test-AgentConfiguration
        
        Write-RecoveryLog "INFO" "Recovery Health Check Results:"
        Write-RecoveryLog "INFO" "  Processes: $($processStatus.AllRunning) (Running: $($processStatus.Running -join ', '))"
        Write-RecoveryLog "INFO" "  Connectivity: $($connectivityStatus.Connected)"
        Write-RecoveryLog "INFO" "  Configuration: $($configStatus.Valid)"
        
        if ($processStatus.AllRunning -and $connectivityStatus.Connected -and $configStatus.Valid) {
            Write-RecoveryLog "INFO" "✅ All recovery health checks passed"
            exit 0
        }
        else {
            Write-RecoveryLog "ERROR" "❌ Recovery health check failed"
            exit 1
        }
    }
    default {
        Write-Host "Usage: monitoring-recovery.ps1 [monitor|stop|health]"
        exit 1
    }
}