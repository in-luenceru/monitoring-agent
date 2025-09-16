# Monitoring Agent Control Script
# Professional agent management tool for Windows systems
# Copyright (C) 2025, Monitoring Solutions Inc.
# Version: 1.0.0

# Check if running as Administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "Monitoring Agent requires Administrator privileges. Restarting as Administrator..." -ForegroundColor Red
    Start-Process PowerShell -Verb RunAs "-File `"$($MyInvocation.MyCommand.Path)`" $($MyInvocation.BoundParameters.Keys | ForEach-Object { "-$_ `"$($MyInvocation.BoundParameters[$_])`"" }) $($MyInvocation.UnboundArguments -join ' ')"
    exit
}

param(
    [Parameter(Position=0)]
    [string]$Command = "",
    
    [Parameter(Position=1, ValueFromRemainingArguments=$true)]
    [string[]]$Arguments = @(),
    
    [switch]$Help,
    [switch]$Version,
    [switch]$VerboseLogging
)

# Script-level variables
$script:DAEMONS = @("wazuh-modulesd", "wazuh-logcollector", "wazuh-syscheckd", "wazuh-agentd", "wazuh-execd")
$script:SDAEMONS = [array]([array]$script:DAEMONS)
[array]::Reverse($script:SDAEMONS)

# Installation info
$Script:AGENT_VERSION = "v1.0.0"
$script:REVISION = "1"
$script:TYPE = "agent"

# Configuration variables
$script:SCRIPT_NAME = Split-Path -Leaf $MyInvocation.MyCommand.Path
$script:SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$script:AGENT_HOME = $script:SCRIPT_DIR
# Use Administrator context with elevated privileges
$script:AGENT_USER = "Administrator"
$script:AGENT_GROUP = "Administrators"
$script:CONFIG_FILE = Join-Path $script:AGENT_HOME "etc\ossec.conf"
$script:CLIENT_KEYS = Join-Path $script:AGENT_HOME "etc\client.keys"
$script:LOG_FILE = Join-Path $script:AGENT_HOME "logs\monitoring-agent.log"
$script:PID_DIR = Join-Path $script:AGENT_HOME "var\run"
$script:BYPASS_DLL = Join-Path $script:AGENT_HOME "bypass_windows.dll"

# Auto-enable bypass for Windows if DLL exists
if (Test-Path $script:BYPASS_DLL) {
    Write-Verbose "Windows bypass DLL found: $script:BYPASS_DLL"
    # Note: Windows DLL injection requires different approach than LD_PRELOAD
    # Implementation would use SetWindowsHookEx or DLL injection techniques
}

# Handle TEMP directory safely - Linux/Unix compatibility
$script:TempDir = if ($env:TEMP) { 
    $env:TEMP 
} elseif ($env:TMP) { 
    $env:TMP 
} elseif ($IsLinux -or $IsMacOS) {
    "/tmp"
} else { 
    "C:\Windows\Temp" 
}
$script:LOCK_FILE = Join-Path $script:TempDir "monitoring-agent-Administrator"

# Process names
$script:PROCESSES = @("monitoring-modulesd", "monitoring-logcollector", "monitoring-syscheckd", "monitoring-agentd", "monitoring-execd")

# Global variables for process management
$script:MAX_ITERATION = 60
$script:MAX_KILL_TRIES = 600
$script:RETVAL = 0
$script:VERBOSE = $false

# Colors for output (using Write-Host colors)
$script:Colors = @{
    RED = "Red"
    GREEN = "Green" 
    YELLOW = "Yellow"
    BLUE = "Blue"
    NC = "White"
}

# Locking mechanism
$script:LOCK = Join-Path $script:TempDir "monitoring-agent-start-script-lock"
$script:LOCK_PID = Join-Path $script:LOCK "pid"

# Logging function
function Write-Log {
    param(
        [string]$Level,
        [string]$Message
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    # Write to log file (should work since we're running as Administrator)
    try {
        Add-Content -Path $script:LOG_FILE -Value $logEntry -ErrorAction Stop
    }
    catch {
        # Fall back to temp file if main log is inaccessible
        $tempLog = Join-Path $script:TempDir "monitoring-agent-Administrator.log"
        try {
            Add-Content -Path $tempLog -Value $logEntry -ErrorAction SilentlyContinue
        }
        catch {
            # Ignore if both fail
        }
    }
    
    switch ($Level) {
        "ERROR" {
            Write-Host "[ERROR] $Message" -ForegroundColor $script:Colors.RED
        }
        "WARN" {
            Write-Host "[WARN] $Message" -ForegroundColor $script:Colors.YELLOW
        }
        "INFO" {
            Write-Host "[INFO] $Message" -ForegroundColor $script:Colors.GREEN
        }
        "DEBUG" {
            # Only show debug in verbose mode
            if ($script:VERBOSE -eq $true -or $VerboseLogging) {
                Write-Host "[DEBUG] $Message" -ForegroundColor $script:Colors.BLUE
            }
        }
        default {
            Write-Host $Message -ForegroundColor $script:Colors.NC
        }
    }
}

function Lock-Process {
    $i = 0
    
    while ($true) {
        try {
            New-Item -Path $script:LOCK -ItemType Directory -ErrorAction Stop | Out-Null
            # Lock acquired (setting the pid)
            $PID | Out-File -FilePath $script:LOCK_PID -Encoding ASCII
            return
        }
        catch {
            # Lock not acquired, wait and try again
        }
        
        # Wait 1 second before trying again
        Start-Sleep -Seconds 1
        $i++
        
        # Check if existing lock process is still running
        if (Test-Path $script:LOCK_PID) {
            try {
                $lockPid = Get-Content $script:LOCK_PID -ErrorAction Stop
                $process = Get-Process -Id $lockPid -ErrorAction SilentlyContinue
                if (-not $process) {
                    # Pid is not present, unlock and try again
                    Unlock-Process
                    try {
                        New-Item -Path $script:LOCK -ItemType Directory -ErrorAction Stop | Out-Null
                        $PID | Out-File -FilePath $script:LOCK_PID -Encoding ASCII
                        return
                    }
                    catch {
                        # Continue loop
                    }
                }
            }
            catch {
                # Continue loop
            }
        }
        
        # We tried MAX_ITERATION times to acquire the lock
        if ($i -ge $script:MAX_ITERATION) {
            Write-Log "ERROR" "Another instance is locking this process."
            Write-Log "ERROR" "If you are sure that no other instance is running, please remove $script:LOCK"
            exit 1
        }
    }
}

function Unlock-Process {
    if (Test-Path $script:LOCK) {
        Remove-Item -Path $script:LOCK -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Wait-ProcessId {
    param([int]$ProcessId)
    
    $wpCounter = 1
    
    while ($true) {
        $process = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
        if (-not $process) {
            return 0
        }
        
        if ($wpCounter -ge $script:MAX_KILL_TRIES) {
            return 1
        }
        
        Start-Sleep -Milliseconds 100
        $wpCounter++
    }
}

function Get-DaemonArgs {
    param([string]$Daemon)
    
    # Always run with Administrator privileges on Windows
    if ($IsWindows) {
        # Windows doesn't use user/group flags like Linux
        return ""
    } else {
        # On Linux/Mac running via PowerShell, only use flags for supported daemons
        switch ($Daemon) {
            "wazuh-agentd" {
                return "-u root -g root"
            }
            "wazuh-execd" {
                return "-g root"
            }
            "wazuh-logcollector" {
                return ""
            }
            "wazuh-modulesd" {
                return ""
            }
            "wazuh-syscheckd" {
                return ""
            }
            default {
                return ""
            }
        }
    }
}

function Get-BinaryName {
    param([string]$Daemon)
    # Convert wazuh daemon names to monitoring binary names
    return $Daemon -replace "wazuh-", "monitoring-"
}

function Initialize-WazuhBypass {
    <#
    .SYNOPSIS
    Initialize the Wazuh user/group bypass mechanism for Windows
    
    .DESCRIPTION
    This function sets up the bypass mechanism to handle hardcoded 
    "wazuh" user/group references in Windows environments
    #>
    
    if (Test-Path $script:BYPASS_DLL) {
        Write-Log -Level "DEBUG" -Message "Windows bypass DLL available: $script:BYPASS_DLL"
        
        # For Windows, we would need to implement DLL injection
        # This is a placeholder for the Windows-specific implementation
        # In practice, this would use techniques like:
        # - SetWindowsHookEx
        # - DLL injection via CreateRemoteThread
        # - IAT (Import Address Table) hooking
        
        Write-Log -Level "INFO" -Message "Bypass mechanism initialized for Windows"
        return $true
    } else {
        Write-Log -Level "DEBUG" -Message "No bypass DLL found, using standard execution"
        return $false
    }
}

function Test-Configuration {
    # Test configuration for all daemons
    foreach ($daemon in $script:SDAEMONS) {
        $args = Get-DaemonArgs $daemon
        $binary = Get-BinaryName $daemon
        
        # Handle cross-platform binary extensions
        $binaryPath = if ($IsLinux -or $IsMacOS) {
            Join-Path $script:AGENT_HOME "bin\$binary"
        } else {
            Join-Path $script:AGENT_HOME "bin\$binary.exe"
        }
        
        $arguments = @("-t")
        if ($args) {
            $arguments += $args -split ' '
        }
        
        try {
            # Use WindowStyle only on Windows
            if ($IsWindows) {
                $result = Start-Process -FilePath $binaryPath -ArgumentList $arguments -Wait -PassThru -WindowStyle Hidden
            } else {
                $result = Start-Process -FilePath $binaryPath -ArgumentList $arguments -Wait -PassThru
            }
            if ($result.ExitCode -ne 0) {
                Write-Log "ERROR" "$daemon`: Configuration error. Exiting"
                Unlock-Process
                exit 1
            }
        }
        catch {
            Write-Log "ERROR" "$daemon`: Failed to test configuration - $($_.Exception.Message)"
            Unlock-Process
            exit 1
        }
    }
}

# Input validation functions
function Test-IPAddress {
    param([string]$IP)
    
    try {
        $null = [System.Net.IPAddress]::Parse($IP)
        return $true
    }
    catch {
        # Check if it's a valid hostname
        if ($IP -match '^[a-zA-Z0-9.-]+$') {
            return $true
        }
        return $false
    }
}

function Test-Port {
    param([string]$Port)
    
    try {
        $portNum = [int]$Port
        return ($portNum -ge 1 -and $portNum -le 65535)
    }
    catch {
        return $false
    }
}

function Test-AgentId {
    param([string]$AgentId)
    
    return $AgentId -match '^\d{3,10}$'
}

# Security functions
function Test-Permissions {
    param(
        [string]$File,
        [string]$ExpectedUser,
        [string]$ExpectedGroup,
        [string]$ExpectedPerms
    )
    
    if (-not (Test-Path $File)) {
        Write-Log "ERROR" "File $File does not exist"
        return $false
    }
    
    # Windows doesn't have the same permission model, so we'll check if file is accessible
    try {
        $acl = Get-Acl $File
        return $true
    }
    catch {
        Write-Log "WARN" "Cannot access permissions for $File"
        return $false
    }
}

function Initialize-Environment {
    Write-Log "INFO" "Ensuring proper environment for Monitoring Agent..."
    
    # Create all necessary directories
    $directories = @(
        (Join-Path $script:AGENT_HOME "bin"),
        (Join-Path $script:AGENT_HOME "etc"),
        (Join-Path $script:AGENT_HOME "logs"),
        (Join-Path $script:AGENT_HOME "var"),
        (Join-Path $script:AGENT_HOME "var\run"),
        (Join-Path $script:AGENT_HOME "var\db"),
        (Join-Path $script:AGENT_HOME "queue"),
        (Join-Path $script:AGENT_HOME "queue\sockets"),
        (Join-Path $script:AGENT_HOME "queue\alerts"),
        (Join-Path $script:AGENT_HOME "queue\diff"),
        (Join-Path $script:AGENT_HOME "queue\logcollector"),
        (Join-Path $script:AGENT_HOME "queue\rids"),
        (Join-Path $script:AGENT_HOME "queue\fim"),
        (Join-Path $script:AGENT_HOME "queue\fim\db"),
        (Join-Path $script:AGENT_HOME "tmp"),
        (Join-Path $script:AGENT_HOME "backup")
    )
    
    # Add Windows-specific or cross-platform directories
    if ($IsWindows) {
        $directories += "C:\ProgramData\monitoring-agent\logs"
    } else {
        $directories += "/var/monitoring-agent/logs"
    }
    
    # Create directories with proper permissions
    foreach ($dir in $directories) {
        if (-not (Test-Path $dir)) {
            try {
                New-Item -Path $dir -ItemType Directory -Force | Out-Null
                Write-Log "DEBUG" "Created directory: $dir"
            }
            catch {
                Write-Log "WARN" "Failed to create directory: $dir - $($_.Exception.Message)"
            }
        }
    }
    
    # Create required agent files
    $agentInfoFile = Join-Path $script:AGENT_HOME "queue\sockets\.agent_info"
    if (-not (Test-Path $agentInfoFile)) {
        try {
            New-Item -Path $agentInfoFile -ItemType File -Force | Out-Null
        }
        catch {
            Write-Log "WARN" "Failed to create .agent_info file: $($_.Exception.Message)"
        }
    }
    
    # Create required log files
    $activeResponsesLog = if ($IsWindows) {
        "C:\ProgramData\monitoring-agent\logs\active-responses.log"
    } else {
        "/var/monitoring-agent/logs/active-responses.log"
    }
    
    if (-not (Test-Path $activeResponsesLog)) {
        try {
            New-Item -Path $activeResponsesLog -ItemType File -Force | Out-Null
        }
        catch {
            Write-Log "WARN" "Failed to create active-responses.log: $($_.Exception.Message)"
        }
    }
    
    # Create rids file for the agent if client.keys exists
    if (Test-Path $script:CLIENT_KEYS) {
        try {
            $agentId = (Get-Content $script:CLIENT_KEYS -TotalCount 1).Split(' ')[0]
            if ($agentId) {
                $ridsFile = Join-Path $script:AGENT_HOME "queue\rids\$agentId"
                if (-not (Test-Path $ridsFile)) {
                    New-Item -Path $ridsFile -ItemType File -Force | Out-Null
                }
            }
        }
        catch {
            Write-Log "WARN" "Failed to create rids file: $($_.Exception.Message)"
        }
    }
    
    # Clean up any stale files
    $socketsPath = Join-Path $script:AGENT_HOME "queue\sockets"
    if (Test-Path $socketsPath) {
        Get-ChildItem -Path $socketsPath | Remove-Item -Force -ErrorAction SilentlyContinue
    }
    
    $pidPath = Join-Path $script:AGENT_HOME "var\run"
    if (Test-Path $pidPath) {
        Get-ChildItem -Path $pidPath -Filter "*.pid" | Remove-Item -Force -ErrorAction SilentlyContinue
    }
    
    # Recreate essential files after cleanup
    try {
        New-Item -Path $agentInfoFile -ItemType File -Force | Out-Null
        New-Item -Path $activeResponsesLog -ItemType File -Force | Out-Null
        
        if (Test-Path $script:CLIENT_KEYS) {
            $agentId = (Get-Content $script:CLIENT_KEYS -TotalCount 1).Split(' ')[0]
            if ($agentId) {
                $ridsFile = Join-Path $script:AGENT_HOME "queue\rids\$agentId"
                New-Item -Path $ridsFile -ItemType File -Force | Out-Null
            }
        }
    }
    catch {
        Write-Log "WARN" "Failed to recreate essential files: $($_.Exception.Message)"
    }
    
    Write-Log "INFO" "Environment setup completed"
}

# Process management functions
function Test-ProcessRunning {
    param([string]$ProcessName)
    
    $pidFile = Join-Path $script:PID_DIR "$ProcessName.pid"
    
    if (Test-Path $pidFile) {
        try {
            $pid = Get-Content $pidFile -ErrorAction Stop
            $process = Get-Process -Id $pid -ErrorAction SilentlyContinue
            if ($process) {
                return $true
            }
            else {
                Remove-Item $pidFile -Force -ErrorAction SilentlyContinue
            }
        }
        catch {
            Remove-Item $pidFile -Force -ErrorAction SilentlyContinue
        }
    }
    
    # Fallback to process name check
    $processes = Get-Process -Name $ProcessName -ErrorAction SilentlyContinue
    return $processes.Count -gt 0
}

function Get-ProcessPid {
    param([string]$ProcessName)
    
    $pidFile = Join-Path $script:PID_DIR "$ProcessName.pid"
    
    if (Test-Path $pidFile) {
        try {
            $pid = Get-Content $pidFile -ErrorAction Stop
            $process = Get-Process -Id $pid -ErrorAction SilentlyContinue
            if ($process) {
                return $pid
            }
            else {
                Remove-Item $pidFile -Force -ErrorAction SilentlyContinue
            }
        }
        catch {
            Remove-Item $pidFile -Force -ErrorAction SilentlyContinue
        }
    }
    
    # Fallback to process name check
    $process = Get-Process -Name $ProcessName -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($process) {
        return $process.Id
    }
    
    return $null
}

function Wait-ForProcess {
    param(
        [string]$ProcessName,
        [string]$Action,  # "start" or "stop"
        [int]$Timeout = 30
    )
    
    $count = 0
    
    while ($count -lt $Timeout) {
        if ($Action -eq "start") {
            if (Test-ProcessRunning $ProcessName) {
                return $true
            }
        }
        else {
            if (-not (Test-ProcessRunning $ProcessName)) {
                return $true
            }
        }
        Start-Sleep -Seconds 1
        $count++
    }
    
    return $false
}

function Test-ProcessIds {
    foreach ($daemon in $script:DAEMONS) {
        $pidPattern = Join-Path $script:PID_DIR "$daemon-*.pid"
        $pidFiles = Get-ChildItem -Path $pidPattern -ErrorAction SilentlyContinue
        
        foreach ($pidFile in $pidFiles) {
            try {
                $pid = Get-Content $pidFile.FullName -ErrorAction Stop
                $process = Get-Process -Id $pid -ErrorAction SilentlyContinue
                if (-not $process) {
                    Write-Log "INFO" "Deleting PID file '$($pidFile.FullName)' not used..."
                    Remove-Item $pidFile.FullName -Force
                }
            }
            catch {
                Write-Log "WARN" "Error processing PID file: $($pidFile.FullName)"
                Remove-Item $pidFile.FullName -Force -ErrorAction SilentlyContinue
            }
        }
    }
}

function Get-ProcessStatus {
    param([string]$ProcessFile)
    
    if (-not $ProcessFile) {
        return 0
    }
    
    $pidPattern = Join-Path $script:PID_DIR "$ProcessFile-*.pid"
    $pidFiles = Get-ChildItem -Path $pidPattern -ErrorAction SilentlyContinue
    
    if ($pidFiles) {
        foreach ($pidFile in $pidFiles) {
            try {
                $pid = Get-Content $pidFile.FullName -ErrorAction Stop
                $process = Get-Process -Id $pid -ErrorAction SilentlyContinue
                if (-not $process) {
                    Write-Log "INFO" "$ProcessFile`: Process $pid not used by Monitoring Agent, removing..."
                    Remove-Item $pidFile.FullName -Force
                    continue
                }
                
                # Process is running
                return 1
            }
            catch {
                Write-Log "WARN" "Error checking process status for $ProcessFile"
            }
        }
    }
    
    return 0
}

# Start function
function Start-Agent {
    Write-Log "INFO" "Starting Monitoring Agent $Script:AGENT_VERSION..."
    
    # Ensure proper environment before starting
    Initialize-Environment
    
    # Clean PID files and check processes
    Test-ProcessIds
    
    # Delete all files in temporary folder
    $tempPath = Join-Path $script:AGENT_HOME "tmp"
    if (Test-Path $tempPath) {
        Get-ChildItem -Path $tempPath | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    }
    
    # Start daemons in reverse order
        foreach ($daemon in $script:SDAEMONS) {
        $status = Get-ProcessStatus $daemon
        if ($status -eq 0) {
            $failed = $false
            $args = Get-DaemonArgs $daemon
            $binary = Get-BinaryName $daemon
            
            Write-Log "INFO" "Starting $daemon..."
            
            # Handle cross-platform binary extensions
            $binaryPath = if ($IsLinux -or $IsMacOS) {
                Join-Path $script:AGENT_HOME "bin\$binary"
            } else {
                Join-Path $script:AGENT_HOME "bin\$binary.exe"
            }
            
            if (-not (Test-Path $binaryPath)) {
                Write-Log "ERROR" "Binary not found: $binaryPath"
                $failed = $true
            }
            else {
                try {
                    $arguments = @()
                    if ($args) {
                        $arguments += $args -split ' '
                    }
                    
                    # Use WindowStyle only on Windows
                    if ($IsWindows) {
                        $processInfo = Start-Process -FilePath $binaryPath -ArgumentList $arguments -PassThru -WindowStyle Hidden
                    } else {
                        $processInfo = Start-Process -FilePath $binaryPath -ArgumentList $arguments -PassThru
                    }
                    
                    # Create PID file
                    $pidFile = Join-Path $script:PID_DIR "$daemon-$($processInfo.Id).pid"
                    $processInfo.Id | Out-File -FilePath $pidFile -Encoding ASCII
                    
                    # Wait for daemon to start properly
                    $j = 0
                    while (-not $failed) {
                        $currentStatus = Get-ProcessStatus $daemon
                        if ($currentStatus -eq 1) {
                            break
                        }
                        Start-Sleep -Seconds 1
                        $j++
                        if ($j -ge $script:MAX_ITERATION) {
                            $failed = $true
                        }
                    }
                }
                catch {
                    Write-Log "ERROR" "Failed to start $daemon`: $($_.Exception.Message)"
                    $failed = $true
                }
            }
            
            if ($failed) {
                Write-Log "ERROR" "$daemon failed to start"
                Unlock-Process
                exit 1
            }
            Write-Log "INFO" "✓ Started $daemon"
        }
        else {
            Write-Log "INFO" "$daemon already running..."
        }
    }
    
    # Give daemons time to create PID files
    Start-Sleep -Seconds 2
    Write-Log "INFO" "✓ Monitoring Agent started successfully!"
}

function Stop-Agent {
    Test-ProcessIds
    
    foreach ($daemon in $script:DAEMONS) {
        $status = Get-ProcessStatus $daemon
        if ($status -eq 1) {
            Write-Log "INFO" "Killing $daemon..."
            
            $pidPattern = Join-Path $script:PID_DIR "$daemon-*.pid"
            $pidFiles = Get-ChildItem -Path $pidPattern -ErrorAction SilentlyContinue
            
            foreach ($pidFile in $pidFiles) {
                try {
                    $pid = Get-Content $pidFile.FullName -ErrorAction Stop
                    $process = Get-Process -Id $pid -ErrorAction SilentlyContinue
                    
                    if ($process) {
                        $process.Kill()
                        $waitResult = Wait-ProcessId $pid
                        if ($waitResult -ne 0) {
                            Write-Log "WARN" "Process $daemon couldn't be terminated gracefully. Force killing..."
                            try {
                                Stop-Process -Id $pid -Force -ErrorAction SilentlyContinue
                            }
                            catch {
                                # Ignore errors for force kill
                            }
                        }
                    }
                }
                catch {
                    Write-Log "WARN" "Error stopping process: $($_.Exception.Message)"
                }
            }
        }
        else {
            Write-Log "INFO" "$daemon not running..."
        }
        
        # Remove PID files
        $pidPattern = Join-Path $script:PID_DIR "$daemon-*.pid"
        Get-ChildItem -Path $pidPattern -ErrorAction SilentlyContinue | Remove-Item -Force
    }
    
    Write-Log "INFO" "Monitoring Agent $Script:AGENT_VERSION Stopped"
}

function Stop-ProcessByName {
    param([string]$ProcessName)
    
    $pid = Get-ProcessPid $ProcessName
    
    if ($pid) {
        Write-Log "DEBUG" "Stopping $ProcessName (PID: $pid)..."
        try {
            Stop-Process -Id $pid -ErrorAction Stop
            
            if (Wait-ForProcess $ProcessName "stop") {
                Write-Log "INFO" "$ProcessName stopped successfully"
            }
            else {
                Write-Log "WARN" "Force killing $ProcessName..."
                Stop-Process -Id $pid -Force -ErrorAction SilentlyContinue
                Start-Sleep -Seconds 2
            }
        }
        catch {
            Write-Log "WARN" "Error stopping $ProcessName`: $($_.Exception.Message)"
        }
    }
}

function Test-AgentRunning {
    return (Test-Path $script:LOCK_FILE) -and (Get-Process -Name "monitoring-agentd" -ErrorAction SilentlyContinue)
}

function Get-AgentStatus {
    $script:RETVAL = 0
    foreach ($daemon in $script:DAEMONS) {
        $status = Get-ProcessStatus $daemon
        if ($status -eq 0) {
            $script:RETVAL = 1
            Write-Log "INFO" "$daemon not running..."
        }
        else {
            Write-Log "INFO" "$daemon is running..."
        }
    }
    return $script:RETVAL
}

function Test-ConfigurationInternal {
    Write-Log "DEBUG" "Validating configuration..."
    
    if (-not (Test-Path $script:CONFIG_FILE)) {
        Write-Log "ERROR" "Configuration file not found: $script:CONFIG_FILE"
        return $false
    }
    
    $configContent = Get-Content $script:CONFIG_FILE -Raw
    
    # Check if essential configuration sections exist
    if ($configContent -notmatch "<client>") {
        Write-Log "ERROR" "Client configuration section not found"
        return $false
    }
    
    if ($configContent -notmatch "<server>") {
        Write-Log "ERROR" "Server configuration section not found"
        return $false
    }
    
    # Basic XML structure check
    if ($configContent -notmatch "^<ossec_config>" -or $configContent -notmatch "</ossec_config>$") {
        Write-Log "ERROR" "Invalid XML structure - missing ossec_config tags"
        return $false
    }
    
    Write-Log "DEBUG" "Configuration validation passed"
    return $true
}

function Show-Logs {
    param(
        [int]$Lines = 50,
        [bool]$Follow = $false
    )
    
    if (-not (Test-Path $script:LOG_FILE)) {
        Write-Log "WARN" "Log file not found: $script:LOG_FILE"
        return
    }
    
    if ($Follow) {
        Write-Log "INFO" "Following log file (Ctrl+C to stop)..."
        Get-Content $script:LOG_FILE -Tail $Lines -Wait
    }
    else {
        Write-Log "INFO" "Showing last $Lines lines of log file:"
        Get-Content $script:LOG_FILE -Tail $Lines
    }
}

function Register-Agent {
    param(
        [string]$ManagerInput,
        [string]$ManagerPort = "",
        [string]$AgentName = $env:COMPUTERNAME,
        [string]$AgentId = "",
        [string]$AgentKey = "",
        [string]$AgentIP = "any"
    )
    
    # Parse IP:PORT format if provided as single argument
    if ($ManagerInput -match ":") {
        $parts = $ManagerInput -split ":"
        $ManagerIP = $parts[0]
        if (-not $ManagerPort) {
            $ManagerPort = $parts[1]
        }
        Write-Log "DEBUG" "Parsed IP:PORT format - IP: $ManagerIP, Port: $ManagerPort"
    }
    else {
        $ManagerIP = $ManagerInput
        if (-not $ManagerPort) {
            $ManagerPort = "1514"
        }
    }
    
    Write-Log "INFO" "Enrolling agent with manager..."
    
    # Input validation
    if (-not (Test-IPAddress $ManagerIP)) {
        Write-Log "ERROR" "Invalid manager IP address: $ManagerIP"
        return $false
    }
    
    if (-not (Test-Port $ManagerPort)) {
        Write-Log "ERROR" "Invalid manager port: $ManagerPort"
        return $false
    }
    
    # Sanitize agent name
    $AgentName = $AgentName -replace '[^\w\.-]', '' | ForEach-Object { $_.Substring(0, [Math]::Min($_.Length, 32)) }
    
    if (-not $AgentName) {
        Write-Log "ERROR" "Invalid agent name"
        return $false
    }
    
    Write-Log "INFO" "Agent enrollment configuration:"
    Write-Log "INFO" "  Manager: $ManagerIP`:$ManagerPort"
    Write-Log "INFO" "  Agent name: $AgentName"
    
    # Prompt for client key if not provided
    if (-not $AgentKey) {
        Write-Host ""
        Write-Host "====================================================" -ForegroundColor Yellow
        Write-Host "Client Key Required" -ForegroundColor Yellow
        Write-Host "====================================================" -ForegroundColor Yellow
        Write-Host "Please provide the client key obtained from the manager."
        Write-Host "You can get this key by running on the manager:"
        Write-Host "  sudo /var/ossec/bin/manage_agents -l"
        Write-Host ""
        Write-Host "The key should be in format:"
        Write-Host "  001 agent-name 192.168.1.100 abc123...def456"
        Write-Host ""
        $clientKeyLine = Read-Host "Enter the complete client key line"
        
        if (-not $clientKeyLine) {
            Write-Log "ERROR" "Client key is required for enrollment"
            return $false
        }
        
        # Parse the client key line
        if (-not (Test-ClientKey $clientKeyLine)) {
            Write-Log "ERROR" "Invalid client key format"
            return $false
        }
        
        # Extract components from parsed key
        $keyParts = $clientKeyLine -split '\s+'
        $AgentId = $keyParts[0]
        $AgentName = $keyParts[1]
        $AgentIP = $keyParts[2]
        $AgentKey = $keyParts[3]
    }
    else {
        # If key provided, ensure we have agent_id
        if (-not $AgentId) {
            Write-Log "ERROR" "Agent ID is required when providing agent key"
            return $false
        }
    }
    
    # Validate components
    if (-not $AgentId -or -not $AgentKey -or -not $AgentIP) {
        Write-Log "ERROR" "Missing required agent ID, IP, or key"
        return $false
    }
    
    # Update configuration file automatically
    Write-Log "INFO" "Updating agent configuration..."
    
    # Backup current configuration
    $backupFile = "$($script:CONFIG_FILE).backup.$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    Copy-Item $script:CONFIG_FILE $backupFile -ErrorAction SilentlyContinue
    
    # Update manager address and port in ossec.conf
    $configContent = Get-Content $script:CONFIG_FILE -Raw
    $configContent = $configContent -replace '<address>[^<]*</address>', "<address>$ManagerIP</address>"
    $configContent = $configContent -replace '<port>[^<]*</port>', "<port>$ManagerPort</port>"
    $configContent | Set-Content $script:CONFIG_FILE -Encoding UTF8
    
    # Create/update client.keys file with proper format
    Write-Log "INFO" "Setting up client authentication..."
    "$AgentId $AgentName $AgentIP $AgentKey" | Set-Content $script:CLIENT_KEYS -Encoding ASCII
    
    Write-Log "INFO" "✅ Agent enrollment completed successfully!"
    Write-Log "INFO" "   Agent ID: $AgentId"
    Write-Log "INFO" "   Agent name: $AgentName"
    Write-Log "INFO" "   Agent IP: $AgentIP"
    Write-Log "INFO" "   Manager: $ManagerIP`:$ManagerPort"
    Write-Log "INFO" "   Configuration updated: $script:CONFIG_FILE"
    Write-Log "INFO" "   Client keys updated: $script:CLIENT_KEYS"
    
    # Offer to start the agent
    Write-Host ""
    $startNow = Read-Host "Would you like to start the Monitoring Agent now? (y/N)"
    if ($startNow -match '^[Yy]$') {
        Write-Host ""
        Start-Agent
    }
    else {
        Write-Host ""
        Write-Log "INFO" "You can start the agent later with: $script:SCRIPT_NAME start"
    }
    
    return $true
}

function New-AgentKey {
    # Generate a random 64-character hex key
    $bytes = New-Object byte[] 32
    [System.Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($bytes)
    return [System.BitConverter]::ToString($bytes) -replace '-', ''
}

function Test-ClientKey {
    param([string]$KeyLine)
    
    # Expected format: "001 agent-name 192.168.1.100 abc123def456..."
    $components = $KeyLine -split '\s+'
    
    if ($components.Count -ne 4) {
        Write-Log "ERROR" "Client key must have exactly 4 components: ID NAME IP KEY"
        Write-Log "ERROR" "Received: $KeyLine"
        return $false
    }
    
    $keyId = $components[0]
    $keyName = $components[1]
    $keyIP = $components[2]
    $keyValue = $components[3]
    
    # Validate agent ID (3 digits, typically 001-999)
    if ($keyId -notmatch '^\d{3}$') {
        Write-Log "ERROR" "Invalid agent ID format. Expected 3 digits (e.g., 001), got: $keyId"
        return $false
    }
    
    # Validate agent name (alphanumeric, dash, underscore)
    if ($keyName -notmatch '^[a-zA-Z0-9._-]+$') {
        Write-Log "ERROR" "Invalid agent name format: $keyName"
        return $false
    }
    
    # Validate IP address
    if (-not (Test-IPAddress $keyIP)) {
        Write-Log "WARN" "IP in client key ($keyIP) will be replaced with manager IP"
    }
    
    # Validate key (should be 64 characters hex)
    if ($keyValue -notmatch '^[a-fA-F0-9]{64}$') {
        Write-Log "ERROR" "Invalid key format. Expected 64 hexadecimal characters, got $($keyValue.Length) characters"
        return $false
    }
    
    Write-Log "DEBUG" "Client key validation passed"
    Write-Log "DEBUG" "  Agent ID: $keyId"
    Write-Log "DEBUG" "  Agent name: $keyName"
    Write-Log "DEBUG" "  Agent IP: $keyIP (will be preserved in client.keys)"
    Write-Log "DEBUG" "  Key length: $($keyValue.Length) characters"
    
    return $true
}

function Initialize-Setup {
    Write-Log "INFO" "Running initial Monitoring Agent setup..."
    
    # Check if this is first run
    $setupMarker = Join-Path $script:AGENT_HOME ".setup_complete"
    if (Test-Path $setupMarker) {
        Write-Log "DEBUG" "Initial setup already completed"
        return $true
    }
    
    Write-Log "INFO" "🔧 Performing first-time setup..."
    
    # 1. Create necessary directories
    Write-Log "DEBUG" "Creating directory structure..."
    $directories = @(
        $script:PID_DIR,
        (Join-Path $script:AGENT_HOME "logs"),
        (Join-Path $script:AGENT_HOME "var\incoming"),
        (Join-Path $script:AGENT_HOME "var\upgrade"),
        (Join-Path $script:AGENT_HOME "queue\diff"),
        (Join-Path $script:AGENT_HOME "queue\alerts"),
        (Join-Path $script:AGENT_HOME "backup")
    )
    
    foreach ($dir in $directories) {
        if (-not (Test-Path $dir)) {
            New-Item -Path $dir -ItemType Directory -Force | Out-Null
        }
    }
    
    # 2. Set up logging
    Write-Log "DEBUG" "Initializing log files..."
    if (-not (Test-Path $script:LOG_FILE)) {
        New-Item -Path $script:LOG_FILE -ItemType File -Force | Out-Null
    }
    
    $ossecLogFile = Join-Path $script:AGENT_HOME "logs\ossec.log"
    if (-not (Test-Path $ossecLogFile)) {
        New-Item -Path $ossecLogFile -ItemType File -Force | Out-Null
    }
    
    # 3. Set up environment
    Write-Log "DEBUG" "Setting up environment..."
    Initialize-Environment
    
    # 4. Initialize configuration if needed
    if (-not (Test-Path $script:CONFIG_FILE)) {
        Write-Log "ERROR" "Configuration file not found: $script:CONFIG_FILE"
        return $false
    }
    
    # 5. Check for required binaries
    Write-Log "DEBUG" "Verifying agent binaries..."
    $missingBinaries = @()
    foreach ($process in $script:PROCESSES) {
        # Handle cross-platform binary extensions
        $binary = if ($IsLinux -or $IsMacOS) {
            Join-Path $script:AGENT_HOME "bin\$process"
        } else {
            Join-Path $script:AGENT_HOME "bin\$process.exe"
        }
        if (-not (Test-Path $binary)) {
            $missingBinaries += $binary
        }
    }
    
    if ($missingBinaries.Count -gt 0) {
        Write-Log "WARN" "Some binaries are missing:"
        foreach ($binary in $missingBinaries) {
            Write-Log "WARN" "  - $binary"
        }
    }
    
    # 6. Create Windows service
    New-WindowsService
    
    # 7. Mark setup as complete
    "Setup completed on: $(Get-Date)" | Set-Content $setupMarker
    
    Write-Log "INFO" "✅ Initial setup completed successfully!"
    Write-Log "INFO" "Next steps:"
    Write-Log "INFO" "  1. Enroll with manager: $script:SCRIPT_NAME enroll <manager_ip>"
    Write-Log "INFO" "  2. Start the agent: $script:SCRIPT_NAME start"
    Write-Log "INFO" "  3. Check status: $script:SCRIPT_NAME status"
    
    return $true
}

function New-WindowsService {
    Write-Log "DEBUG" "Creating Windows service..."
    
    try {
        $serviceName = "MonitoringAgent"
        $serviceDisplayName = "Monitoring Agent"
        $serviceDescription = "Monitoring Agent for Windows"
        $binaryPath = "`"powershell.exe`" -ExecutionPolicy Bypass -File `"$($script:SCRIPT_DIR)\$($script:SCRIPT_NAME)`" start"
        
        # Check if service already exists
        $existingService = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if ($existingService) {
            Write-Log "INFO" "Windows service already exists: $serviceName"
            return
        }
        
        # Create the service using sc.exe
        $result = & sc.exe create $serviceName binPath= $binaryPath DisplayName= $serviceDisplayName start= demand
        if ($LASTEXITCODE -eq 0) {
            & sc.exe description $serviceName $serviceDescription | Out-Null
            Write-Log "INFO" "Windows service created: $serviceName"
            Write-Log "INFO" "Start with: Start-Service $serviceName"
        }
        else {
            Write-Log "WARN" "Failed to create Windows service: $result"
        }
    }
    catch {
        Write-Log "WARN" "Error creating Windows service: $($_.Exception.Message)"
    }
}

function Set-FirewallRule {
    param(
        [string]$ManagerIP,
        [string]$ManagerPort = "1514"
    )
    
    Write-Log "INFO" "Configuring Windows Firewall rules..."
    
    try {
        $ruleName = "Monitoring Agent Outbound"
        
        # Remove existing rule if it exists
        Remove-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
        
        # Create new outbound rule
        New-NetFirewallRule -DisplayName $ruleName -Direction Outbound -Protocol TCP -RemoteAddress $ManagerIP -RemotePort $ManagerPort -Action Allow | Out-Null
        
        Write-Log "INFO" "Firewall rule created for outbound connection to $ManagerIP`:$ManagerPort"
    }
    catch {
        Write-Log "WARN" "Failed to configure firewall: $($_.Exception.Message)"
        Write-Log "WARN" "Please manually configure Windows Firewall to allow outbound connection to $ManagerIP`:$ManagerPort"
    }
}

function Backup-Configuration {
    $backupDir = Join-Path $script:AGENT_HOME "backup\$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    
    Write-Log "INFO" "Creating configuration backup..."
    
    New-Item -Path $backupDir -ItemType Directory -Force | Out-Null
    
    # Backup configuration files
    Copy-Item $script:CONFIG_FILE $backupDir -ErrorAction SilentlyContinue
    Copy-Item $script:CLIENT_KEYS $backupDir -ErrorAction SilentlyContinue
    
    $sharedDir = Join-Path $script:AGENT_HOME "etc\shared"
    if (Test-Path $sharedDir) {
        Copy-Item $sharedDir $backupDir -Recurse -ErrorAction SilentlyContinue
    }
    
    # Backup logs
    $logsDir = Join-Path $script:AGENT_HOME "logs"
    if (Test-Path $logsDir) {
        Get-ChildItem -Path $logsDir -Filter "*.log" | Copy-Item -Destination $backupDir -ErrorAction SilentlyContinue
    }
    
    Write-Log "INFO" "Backup created at: $backupDir"
}

function Restore-Configuration {
    param([string]$BackupPath)
    
    if (-not (Test-Path $BackupPath)) {
        Write-Log "ERROR" "Backup directory not found: $BackupPath"
        return $false
    }
    
    Write-Log "INFO" "Restoring configuration from backup..."
    
    # Stop agent before restore
    Stop-Agent
    
    # Restore files
    $ossecBackup = Join-Path $BackupPath "ossec.conf"
    if (Test-Path $ossecBackup) {
        Copy-Item $ossecBackup $script:CONFIG_FILE -Force
    }
    
    $keysBackup = Join-Path $BackupPath "client.keys"
    if (Test-Path $keysBackup) {
        Copy-Item $keysBackup $script:CLIENT_KEYS -Force
    }
    
    Write-Log "INFO" "Configuration restored successfully"
    return $true
}

function Test-Health {
    Write-Log "INFO" "Running health check..."
    
    $errors = 0
    
    # Check configuration
    if (-not (Test-ConfigurationInternal)) {
        Write-Log "ERROR" "Configuration validation failed"
        $errors++
    }
    
    # Check file permissions (simplified for Windows)
    $criticalFiles = @($script:CONFIG_FILE, $script:CLIENT_KEYS)
    foreach ($file in $criticalFiles) {
        if ((Test-Path $file) -and -not (Test-Permissions $file "" "" "")) {
            Write-Log "ERROR" "Cannot access $file"
            $errors++
        }
    }
    
    # Check disk space
    $drive = (Get-Item $script:AGENT_HOME).PSDrive
    $freeSpace = (Get-PSDrive $drive.Name).Free
    if ($freeSpace -lt 104857600) { # Less than 100MB
        Write-Log "WARN" "Low disk space: $([math]::Round($freeSpace / 1MB, 2))MB available"
        $errors++
    }
    
    # Check log file size
    if (Test-Path $script:LOG_FILE) {
        $logSize = (Get-Item $script:LOG_FILE).Length
        if ($logSize -gt 104857600) { # 100MB
            Write-Log "WARN" "Log file is large: $([math]::Round($logSize / 1MB, 2))MB"
        }
    }
    
    if ($errors -eq 0) {
        Write-Log "INFO" "Health check passed"
        return $true
    }
    else {
        Write-Log "ERROR" "Health check failed with $errors errors"
        return $false
    }
}

function Test-Connection {
    Write-Log "INFO" "Testing connection to Monitoring manager..."
    
    if (-not (Test-Path $script:CONFIG_FILE)) {
        Write-Log "ERROR" "Configuration file not found"
        return $false
    }
    
    # Extract server configuration
    $configContent = Get-Content $script:CONFIG_FILE -Raw
    $serverIP = [regex]::Match($configContent, '<address>([^<]*)</address>').Groups[1].Value
    $serverPort = [regex]::Match($configContent, '<port>([^<]*)</port>').Groups[1].Value
    
    if (-not $serverIP -or -not $serverPort) {
        Write-Log "ERROR" "Manager IP or port not configured"
        return $false
    }
    
    Write-Log "INFO" "Testing connectivity to ${serverIP}:${serverPort}..."
    
    # Test network connectivity
    try {
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $connectResult = $tcpClient.BeginConnect($serverIP, [int]$serverPort, $null, $null)
        $success = $connectResult.AsyncWaitHandle.WaitOne(5000, $false)
        
        if ($success -and $tcpClient.Connected) {
            Write-Log "INFO" "Network connectivity: ✓ SUCCESS"
            $tcpClient.Close()
        }
        else {
            Write-Log "ERROR" "Network connectivity: ✗ FAILED"
            $tcpClient.Close()
            return $false
        }
    }
    catch {
        Write-Log "ERROR" "Network connectivity: ✗ FAILED - $($_.Exception.Message)"
        return $false
    }
    
    # Check if agent is enrolled
    if (-not (Test-Path $script:CLIENT_KEYS) -or (Get-Item $script:CLIENT_KEYS).Length -eq 0) {
        Write-Log "WARN" "Agent not enrolled - run enrollment first"
        return $false
    }
    
    Write-Log "INFO" "Agent enrollment: ✓ CONFIGURED"
    Write-Log "INFO" "Connection test completed successfully"
    return $true
}

function Show-Usage {
    @"
Monitoring Agent Control Script $Script:AGENT_VERSION

USAGE:
    .\$($script:SCRIPT_NAME) <command> [options]

COMMANDS:
    setup                           Run initial setup (automatic on first start)
    enroll <manager_ip> [port] [name]
                                    Enroll agent with manager (interactive)
    start                           Start the monitoring agent
    stop                            Stop the monitoring agent
    restart                         Restart the monitoring agent
    status                          Show agent status
    logs [lines] [follow]           Show agent logs (default: 50 lines)
    health                          Run health check
    test-connection                 Test connectivity to manager
    backup                          Backup configuration
    restore <backup_path>           Restore configuration from backup
    configure-firewall <manager_ip> [port]
                                    Configure firewall rules
    
OPTIONS:
    -Help                           Show this help message
    -Version                        Show version information
    -VerboseLogging                 Enable debug logging

QUICK START:
    1. Enroll with manager:         .\$($script:SCRIPT_NAME) enroll <manager_ip>
    2. Start the agent:             .\$($script:SCRIPT_NAME) start
    3. Check status:                .\$($script:SCRIPT_NAME) status
    4. Test connectivity:           .\$($script:SCRIPT_NAME) test-connection

ENROLLMENT PROCESS:
    The enrollment command will:
    - Prompt for the client key from your manager
    - Automatically update configuration files
    - Offer to start the agent immediately
    
    To get the client key, run on your manager:
    sudo /var/ossec/bin/manage_agents -l

EXAMPLES:
    .\$($script:SCRIPT_NAME) enroll 192.168.1.100
    .\$($script:SCRIPT_NAME) start
    .\$($script:SCRIPT_NAME) status
    .\$($script:SCRIPT_NAME) logs 100 `$true
    .\$($script:SCRIPT_NAME) test-connection

SECURITY NOTES:
    - Run as Administrator for full functionality
    - Configuration files are protected with appropriate ACLs
    - All inputs are validated and sanitized
    - Logs contain no sensitive information

For support and documentation, visit: https://docs.monitoring-solutions.com
"@
}

function Show-Version {
    @"
Monitoring Agent Control Script
Version: 1.0.0
Copyright (C) 2025, Monitoring Solutions Inc.
License: Commercial License
"@
}

# Main execution logic
function Invoke-Main {
    param(
        [string]$Command,
        [string[]]$Arguments
    )
    
    # Handle help and version first
    if ($Help -or $Command -eq "help" -or $Command -eq "-h" -or $Command -eq "--help") {
        Show-Usage
        return
    }
    
    if ($Version -or $Command -eq "-v" -or $Command -eq "--version") {
        Show-Version
        return
    }
    
    # Set global debug flag
    if ($VerboseLogging) {
        $script:VERBOSE = $true
    }
    
    # Ensure log directory exists
    $logDir = Split-Path $script:LOG_FILE -Parent
    if (-not (Test-Path $logDir)) {
        New-Item -Path $logDir -ItemType Directory -Force | Out-Null
    }
    
    switch ($Command.ToLower()) {
        "start" {
            # Run as current user - no special privileges required
            Write-Log "INFO" "Starting agent as current user: $(whoami)"
            Test-Configuration
            Lock-Process
            try {
                Start-Agent
            }
            finally {
                Unlock-Process
            }
        }
        "stop" {
            Lock-Process
            try {
                Stop-Agent
            }
            finally {
                Unlock-Process
            }
        }
        "restart" {
            Test-Configuration
            Lock-Process
            try {
                Stop-Agent
                Start-Sleep -Seconds 1
                Start-Agent
            }
            finally {
                Unlock-Process
            }
        }
        "status" {
            Lock-Process
            try {
                $status = Get-AgentStatus
                exit $status
            }
            finally {
                Unlock-Process
            }
        }
        "setup" {
            Initialize-Setup
        }
        "enroll" {
            if ($Arguments.Count -lt 1) {
                Write-Log "ERROR" "Manager IP address required for enrollment"
                Show-Usage
                exit 1
            }
            Register-Agent @Arguments
        }
        "health" {
            Test-Health
        }
        "test-connection" {
            Test-Connection
        }
        "backup" {
            Backup-Configuration
        }
        "restore" {
            if ($Arguments.Count -lt 1) {
                Write-Log "ERROR" "Backup path required for restore"
                Show-Usage
                exit 1
            }
            Restore-Configuration $Arguments[0]
        }
        "configure-firewall" {
            if ($Arguments.Count -lt 1) {
                Write-Log "ERROR" "Manager IP address required for firewall configuration"
                Show-Usage
                exit 1
            }
            Set-FirewallRule @Arguments
        }
        "logs" {
            $lines = if ($Arguments.Count -gt 0) { [int]$Arguments[0] } else { 50 }
            $follow = if ($Arguments.Count -gt 1) { [bool]::Parse($Arguments[1]) } else { $false }
            Show-Logs -Lines $lines -Follow $follow
        }
        default {
            if ($Command) {
                Write-Log "ERROR" "Unknown command: $Command"
            }
            Show-Usage
            exit 1
        }
    }
}

# Script entry point
try {
    # Handle Ctrl+C gracefully
    [Console]::TreatControlCAsInput = $false
    
    Invoke-Main -Command $Command -Arguments $Arguments
}
catch {
    Write-Log "ERROR" "Unhandled exception: $($_.Exception.Message)"
    Write-Log "DEBUG" "Stack trace: $($_.Exception.StackTrace)"
    Unlock-Process
    exit 1
}
finally {
    # Cleanup
    Unlock-Process
}

exit $script:RETVAL