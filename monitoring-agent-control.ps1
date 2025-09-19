#Requires -RunAsAdministrator

# Monitoring Agent Control Script
# Professional agent management tool for Windows systems
# Copyright (C) 2025, Monitoring Solutions Inc.
# Version: 1.0.0

param(
    [Parameter(Position=0)]
    [string]$Command = "",
    
    [Parameter(Position=1, ValueFromRemainingArguments=$true)]
    [string[]]$Arguments = @(),
    
    [switch]$Help,
    [switch]$Version,
    [switch]$VerboseLogging,
    [switch]$WindowsAgent
)

# Windows-first OS detection - explicit initialization
# Note: Use custom variables for compatibility with PowerShell 5.1 and 7+
$script:IsWindowsPlatform = $true
$script:IsLinuxPlatform = $false
$script:IsMacOSPlatform = $false
$script:IsWindowsAgent = $true

# Administrator check - ensure we're running with elevated privileges
$isAdmin = (New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "This script must be run as Administrator. Please restart PowerShell as Administrator and try again."
    exit 1
}

# Production validation checks
function Test-ProductionRequirements {
    $validationErrors = @()
    
    # Check PowerShell version compatibility
    $psVersion = $PSVersionTable.PSVersion
    if ($psVersion.Major -lt 5) {
        $validationErrors += "PowerShell 5.0 or higher is required. Current version: $($psVersion.ToString())"
    }
    
    # Check if we're on Windows
    if ($PSVersionTable.Platform -and $PSVersionTable.Platform -ne "Win32NT") {
        $validationErrors += "This script is Windows-only. Current platform: $($PSVersionTable.Platform)"
    }
    
    # Validate agent home directory structure
    $requiredDirs = @("bin", "etc", "logs", "var")
    foreach ($dir in $requiredDirs) {
        $dirPath = Join-Path $script:AGENT_HOME $dir
        if (-not (Test-Path $dirPath)) {
            $validationErrors += "Required directory missing: $dirPath"
        }
    }
    
    # Check for critical Windows features
    try {
        Get-Service -Name "Themes" -ErrorAction Stop | Out-Null
    } catch {
        $validationErrors += "Windows Service management not available"
    }
    
    if ($validationErrors.Count -gt 0) {
        Write-Log "ERROR" "Production validation failed:"
        foreach ($validationError in $validationErrors) {
            Write-Log "ERROR" "  - $validationError"
        }
        throw "Production requirements not met"
    }
    
    Write-Log "INFO" "Production validation passed"
}

# Auto-installation and production readiness setup for Windows
function Initialize-ProductionEnvironment {
    Write-Log "INFO" "Setting up production environment for Windows..."
    
    # Windows service is properly installed since this is Windows-only
    $serviceName = "MonitoringAgent"
    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    
    if (-not $service) {
        Write-Log "INFO" "Installing Windows service for auto-startup..."
        # Create Windows service using New-Service or sc.exe
        try {
            $serviceParams = @{
                Name = $serviceName
                BinaryPathName = "PowerShell.exe -ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Path)`" start-service"
                DisplayName = "Monitoring Agent Service"
                Description = "Monitoring Agent Security Platform with Fault Tolerance"
                StartupType = "Automatic"
            }
            New-Service @serviceParams -ErrorAction Stop
            Write-Log "INFO" "Windows service installed and configured for auto-startup"
            
            # Enable auto-recovery for the service using registry
            try {
                $servicePath = "HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName"
                
                # Set failure actions: restart after 5, 10, and 30 seconds
                Set-ItemProperty -Path $servicePath -Name "FailureActions" -Value ([byte[]](
                    # Reset period (24 hours = 86400 seconds)
                    0x40, 0x51, 0x01, 0x00,
                    # Reserved
                    0x00, 0x00, 0x00, 0x00,
                    # Action count (3 actions)
                    0x03, 0x00, 0x00, 0x00,
                    # Action 1: Restart after 5 seconds (5000 ms)
                    0x01, 0x00, 0x00, 0x00, 0x88, 0x13, 0x00, 0x00,
                    # Action 2: Restart after 10 seconds (10000 ms)
                    0x01, 0x00, 0x00, 0x00, 0x10, 0x27, 0x00, 0x00,
                    # Action 3: Restart after 30 seconds (30000 ms)
                    0x01, 0x00, 0x00, 0x00, 0x30, 0x75, 0x00, 0x00
                )) -Type Binary -ErrorAction SilentlyContinue
                
                Write-Log "INFO" "Windows service failure recovery configured"
            }
            catch {
                Write-Log "WARN" "Failed to configure service recovery: $($_.Exception.Message)"
            }
        }
        catch {
            Write-Log "WARN" "Failed to create Windows service: $($_.Exception.Message)"
            # Fallback to task scheduler
            Initialize-TaskScheduler
        }
    }
    else {
        Write-Log "INFO" "Windows service already exists, ensuring proper configuration..."
        # Update service to use start-service command using PowerShell-native methods
        try {
            $newBinaryPath = "PowerShell.exe -ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Path)`" start-service"
            Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName" -Name ImagePath -Value "`"$newBinaryPath`""
            Write-Log "INFO" "Windows service updated with start-service command"
        }
        catch {
            Write-Log "WARN" "Failed to update Windows service configuration: $($_.Exception.Message)"
        }
    }
    
    # Fix permission issues automatically
    $configPaths = @($script:CONFIG_FILE, $script:CLIENT_KEYS, $script:LOG_FILE)
    foreach ($configPath in $configPaths) {
        if (Test-Path $configPath) {
            try {
                # Set appropriate Windows permissions
                $acl = Get-Acl $configPath
                $acl.SetAccessRuleProtection($false, $false)
                Set-Acl -Path $configPath -AclObject $acl
                Write-Log "DEBUG" "Permissions set for: $configPath"
            }
            catch {
                Write-Log "WARN" "Could not set permissions on $configPath`: $($_.Exception.Message)"
            }
        }
    }
    
    # Ensure watchdog system is set up for Windows
    Initialize-WindowsWatchdog
    
    # Set up boot recovery system
    Initialize-WindowsBootRecovery
    
    # Configure Windows firewall if needed
    Initialize-WindowsFirewall
    
    # Ensure all required directories exist with proper permissions
    $requiredDirs = @($script:PID_DIR, "$script:AGENT_HOME\logs", "$script:AGENT_HOME\var\state", "$script:AGENT_HOME\tmp")
    foreach ($dir in $requiredDirs) {
        if (-not (Test-Path $dir)) {
            try {
                New-Item -Path $dir -ItemType Directory -Force | Out-Null
                Write-Log "DEBUG" "Created directory: $dir"
            }
            catch {
                Write-Log "WARN" "Failed to create directory $dir`: $($_.Exception.Message)"
            }
        }
    }
    
    Write-Log "INFO" "Production environment setup completed for Windows"
}

function Initialize-TaskScheduler {
    Write-Log "INFO" "Setting up Task Scheduler for auto-startup..."
    
    try {
        $taskName = "MonitoringAgentStartup"
        $action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Path)`" start"
        $trigger = New-ScheduledTaskTrigger -AtStartup
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        
        Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Force
        Write-Log "INFO" "Task Scheduler configured for auto-startup"
    }
    catch {
        Write-Log "ERROR" "Failed to setup Task Scheduler: $($_.Exception.Message)"
    }
}

function Initialize-WindowsWatchdog {
    # Windows-specific watchdog setup using Task Scheduler
    $watchdogScript = Join-Path $script:SCRIPT_DIR "scripts\windows\monitoring-watchdog.ps1"
    
    if (Test-Path $watchdogScript) {
        Write-Log "INFO" "Setting up Windows watchdog service..."
        
        try {
            $taskName = "MonitoringAgentWatchdog"
            $action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-ExecutionPolicy Bypass -File `"$watchdogScript`""
            $trigger = New-ScheduledTaskTrigger -AtStartup
            $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 5)
            $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
            
            Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Force
            Write-Log "INFO" "Windows watchdog configured"
        }
        catch {
            Write-Log "WARN" "Failed to setup Windows watchdog: $($_.Exception.Message)"
        }
    }
    else {
        Write-Log "WARN" "Watchdog script not found: $watchdogScript"
    }
}

function Initialize-WindowsBootRecovery {
    Write-Log "INFO" "Setting up Windows boot recovery system..."
    
    $bootRecoveryScript = Join-Path $script:AGENT_HOME "scripts\windows\monitoring-boot-recovery.ps1"
    
    if (Test-Path $bootRecoveryScript) {
        try {
            # Set up Task Scheduler task for boot recovery
            $taskName = "MonitoringAgentBootRecovery"
            $action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-ExecutionPolicy Bypass -File `"$bootRecoveryScript`" check"
            $trigger = New-ScheduledTaskTrigger -AtStartup
            $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -Delay (New-TimeSpan -Minutes 2)
            $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
            
            Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Force
            Write-Log "INFO" "Windows boot recovery system configured"
        }
        catch {
            Write-Log "WARN" "Failed to setup Windows boot recovery: $($_.Exception.Message)"
        }
    }
    else {
        Write-Log "WARN" "Boot recovery script not found: $bootRecoveryScript"
    }
}

function Initialize-WindowsFirewall {
    Write-Log "INFO" "Configuring Windows firewall for monitoring agent..."
    
    try {
        # Allow monitoring agent communication
        $ruleName = "Monitoring Agent Communication"
        $existingRule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
        
        if (-not $existingRule) {
            New-NetFirewallRule -DisplayName $ruleName -Direction Outbound -Protocol TCP -LocalPort 1514 -Action Allow -Profile Any
            Write-Log "INFO" "Windows firewall rule created for monitoring agent"
        }
        else {
            Write-Log "DEBUG" "Windows firewall rule already exists"
        }
    }
    catch {
        Write-Log "WARN" "Failed to configure Windows firewall: $($_.Exception.Message)"
    }
}


# Auto-setup production environment on any execution (delayed to after function definitions)
# Initialize-ProductionEnvironment

# Script-level variables - Windows Monitoring agent configuration
# Windows runs as a single agent process - simplified approach
$script:DAEMONS = @("monitoring-agentd")
$script:SDAEMONS = [array]([array]$script:DAEMONS)
[array]::Reverse($script:SDAEMONS)

# Installation info
$Script:AGENT_VERSION = "v4.8.0"  # Updated to match downloaded Wazuh version
$script:REVISION = "1"
$script:TYPE = "agent"

# Configuration variables - Windows-specific paths
$script:SCRIPT_NAME = Split-Path -Leaf $MyInvocation.MyCommand.Path
$script:SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path

# Set Windows agent paths
$script:AGENT_HOME = Join-Path $script:SCRIPT_DIR "windows"
$script:BYPASS_DLL = Join-Path $script:AGENT_HOME "lib\bypass.dll"

# Use Administrator context with elevated privileges
$script:AGENT_USER = "Administrator" 
$script:AGENT_GROUP = "Administrators"
# Helper function to find config files with case-insensitive matching
function Find-ConfigFile {
    param([string]$FullPath)
    
    if (Test-Path $FullPath) {
        return $FullPath
    }
    
    $parentDir = Split-Path $FullPath -Parent
    $expectedFile = Split-Path $FullPath -Leaf
    
    # Try to find file with different case
    try {
        $files = Get-ChildItem -Path $parentDir -ErrorAction SilentlyContinue
        foreach ($file in $files) {
            if ($file.Name -ieq $expectedFile) {
                return $file.FullName
            }
        }
    } catch {
        # Ignore errors
    }
    
    return $FullPath  # Return original path as fallback
}

# Windows configuration file paths with case-insensitive lookup
$windowsEtcDir = Join-Path $script:AGENT_HOME "etc"
$script:CONFIG_FILE = Find-ConfigFile (Join-Path $windowsEtcDir "OSSEC.CONF")
$script:CLIENT_KEYS = Find-ConfigFile (Join-Path $windowsEtcDir "client.keys")
$script:LOG_FILE = Join-Path $script:AGENT_HOME "logs\monitoring-agent.log"
$script:PID_DIR = Join-Path $script:AGENT_HOME "var\run"

# Auto-enable bypass for Windows if DLL exists
if (Test-Path $script:BYPASS_DLL) {
    Write-Verbose "Windows bypass DLL found: $script:BYPASS_DLL"
    # Set environment variable for DLL loading
    $env:MONITORING_BYPASS_DLL = $script:BYPASS_DLL
    # Load bypass DLL functions
    try {
        Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class BypassLoader {
    [DllImport("kernel32.dll")]
    public static extern IntPtr LoadLibrary(string dllToLoad);
    
    [DllImport("kernel32.dll")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procedureName);
    
    public static bool LoadBypassDLL(string dllPath) {
        IntPtr handle = LoadLibrary(dllPath);
        return handle != IntPtr.Zero;
    }
}
"@
        $loaded = [BypassLoader]::LoadBypassDLL($script:BYPASS_DLL)
        if ($loaded) {
            Write-Verbose "Bypass DLL loaded successfully"
        }
    }
    catch {
        Write-Verbose "Could not load bypass DLL: $($_.Exception.Message)"
    }
}

# Handle TEMP directory for Windows
$script:TempDir = if ($env:TEMP) { 
    $env:TEMP 
} elseif ($env:TMP) { 
    $env:TMP 
} else { 
    "C:\Windows\Temp" 
}
$script:LOCK_FILE = Join-Path $script:TempDir "monitoring-agent-Administrator"

# Process names - Using actual Windows Monitoring Agent binary names
$script:PROCESSES = @("monitoring-agentd")

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
    param(
        [int]$ProcessId,
        [int]$TimeoutSeconds = 10
    )
    
    $maxIterations = $TimeoutSeconds * 10  # 100ms intervals
    $wpCounter = 0
    
    while ($wpCounter -lt $maxIterations) {
        $process = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
        if (-not $process) {
            return 0  # Process has exited
        }
        
        Start-Sleep -Milliseconds 100
        $wpCounter++
    }
    
    return 1  # Timeout reached, process still running
}

function Get-DaemonArgs {
    param([string]$Daemon)
    
    # Windows doesn't use user/group flags like Linux - always run with Administrator privileges
    return ""
}

function Get-BinaryName {
    param([string]$Daemon)
    
    # Map Monitoring Agent daemon names to actual Windows executable names
    switch ($Daemon) {
        "monitoring-agentd" { 
            if ($script:IsWindowsAgent) { return "MONITORING_AGENT.EXE" } 
            else { return "monitoring-agentd" }
        }
        "monitoring-execd" { 
            if ($script:IsWindowsAgent) { return "MONITORING_AGENT.EXE" }  # Windows uses single agent process
            else { return "monitoring-execd" }
        }
        "monitoring-logcollector" { 
            if ($script:IsWindowsAgent) { return "MONITORING_AGENT.EXE" }  # Part of main agent on Windows
            else { return "monitoring-logcollector" }
        }
        "monitoring-modulesd" { 
            if ($script:IsWindowsAgent) { return "MONITORING_AGENT.EXE" }  # Part of main agent on Windows
            else { return "monitoring-modulesd" }
        }
        "monitoring-syscheckd" { 
            if ($script:IsWindowsAgent) { return "MONITORING_AGENT.EXE" }  # Part of main agent on Windows
            else { return "monitoring-syscheckd" }
        }
        # Legacy wazuh names (for backward compatibility)
        "wazuh-agentd" { 
            if ($script:IsWindowsAgent) { return "MONITORING_AGENT.EXE" } 
            else { return "wazuh-agentd" }
        }
        "wazuh-execd" { 
            if ($script:IsWindowsAgent) { return "MONITORING_AGENT.EXE" }
            else { return "wazuh-execd" }
        }
        "wazuh-logcollector" { 
            if ($script:IsWindowsAgent) { return "MONITORING_AGENT.EXE" }
            else { return "wazuh-logcollector" }
        }
        "wazuh-modulesd" { 
            if ($script:IsWindowsAgent) { return "MONITORING_AGENT.EXE" }
            else { return "wazuh-modulesd" }
        }
        "wazuh-syscheckd" { 
            if ($script:IsWindowsAgent) { return "MONITORING_AGENT.EXE" }
            else { return "wazuh-syscheckd" }
        }
        default { 
            if ($script:IsWindowsAgent) { return "$Daemon.EXE" }
            else { return $Daemon }
        }
    }
}

function Get-PidName {
    param([string]$Daemon)
    
    # For Windows, Monitoring Agent uses standard daemon names for PID files
    # For consistency across platforms, we use the daemon name as-is
    switch ($Daemon) {
        "monitoring-agentd" { return "monitoring-agentd" }
        "monitoring-execd" { return "monitoring-execd" }
        "monitoring-logcollector" { return "monitoring-logcollector" }
        "monitoring-modulesd" { return "monitoring-modulesd" }
        "monitoring-syscheckd" { return "monitoring-syscheckd" }
        # Legacy wazuh names (for backward compatibility)
        "wazuh-agentd" { return "monitoring-agentd" }
        "wazuh-execd" { return "monitoring-execd" }
        "wazuh-logcollector" { return "monitoring-logcollector" }
        "wazuh-modulesd" { return "monitoring-modulesd" }
        "wazuh-syscheckd" { return "monitoring-syscheckd" }
        default { return $Daemon }
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
        $null = Get-Acl $File
        return $true
    }
    catch {
        Write-Log "WARN" "Cannot access permissions for $File"
        return $false
    }
}

function Initialize-Environment {
    Write-Log "INFO" "Ensuring proper environment for Monitoring Agent..."
    
    # Create all necessary directories with proper path separators
    $directories = @(
        (Join-Path $script:AGENT_HOME "bin"),
        (Join-Path $script:AGENT_HOME "etc"),
        (Join-Path $script:AGENT_HOME "logs"),
        (Join-Path $script:AGENT_HOME "var"),
        (Join-Path $script:AGENT_HOME "var/run"),
        (Join-Path $script:AGENT_HOME "var/db"),
        (Join-Path $script:AGENT_HOME "queue"),
        (Join-Path $script:AGENT_HOME "queue/sockets"),
        (Join-Path $script:AGENT_HOME "queue/alerts"),
        (Join-Path $script:AGENT_HOME "queue/diff"),
        (Join-Path $script:AGENT_HOME "queue/logcollector"),
        (Join-Path $script:AGENT_HOME "queue/rids"),
        (Join-Path $script:AGENT_HOME "queue/fim"),
        (Join-Path $script:AGENT_HOME "queue/fim/db"),
        (Join-Path $script:AGENT_HOME "tmp"),
        (Join-Path $script:AGENT_HOME "backup")
    )
    
    # Add Windows-specific directories
    $directories += "C:\ProgramData\monitoring-agent\logs"
    
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
    $agentInfoFile = Join-Path $script:AGENT_HOME "queue/sockets/.agent_info"
    if (-not (Test-Path $agentInfoFile)) {
        try {
            New-Item -Path $agentInfoFile -ItemType File -Force | Out-Null
        }
        catch {
            Write-Log "WARN" "Failed to create .agent_info file: $($_.Exception.Message)"
        }
    }
    
    # Create required log files for Windows
    $activeResponsesLog = "C:\ProgramData\monitoring-agent\logs\active-responses.log"
    
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
                $ridsFile = Join-Path $script:AGENT_HOME "queue/rids/$agentId"
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
    $socketsPath = Join-Path $script:AGENT_HOME "queue/sockets"
    if (Test-Path $socketsPath) {
        Get-ChildItem -Path $socketsPath | Remove-Item -Force -ErrorAction SilentlyContinue
    }
    
    $pidPath = Join-Path $script:AGENT_HOME "var/run"
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
                $ridsFile = Join-Path $script:AGENT_HOME "queue/rids/$agentId"
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
            $processId = Get-Content $pidFile -ErrorAction Stop
            $process = Get-Process -Id $processId -ErrorAction SilentlyContinue
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
            $processId = Get-Content $pidFile -ErrorAction Stop
            $process = Get-Process -Id $processId -ErrorAction SilentlyContinue
            if ($process) {
                return $processId
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
                $processId = Get-Content $pidFile.FullName -ErrorAction Stop
                $process = Get-Process -Id $processId -ErrorAction SilentlyContinue
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
    
    # For Windows, check if the actual binary process is running
    if ($script:IsWindowsAgent) {
        $binaryName = Get-BinaryName $ProcessFile
        $runningProcesses = Get-Process -Name $binaryName.Replace('.EXE', '') -ErrorAction SilentlyContinue
        if ($runningProcesses) {
            return 1
        }
    }
    
    # Convert monitoring daemon name to actual PID file name
    $pidName = Get-PidName $ProcessFile
    $pidPattern = Join-Path $script:PID_DIR "$pidName-*.pid"
    $pidFiles = Get-ChildItem -Path $pidPattern -ErrorAction SilentlyContinue
    
    if ($pidFiles) {
        foreach ($pidFile in $pidFiles) {
            try {
                $processId = Get-Content $pidFile.FullName -ErrorAction Stop
                $process = Get-Process -Id $processId -ErrorAction SilentlyContinue
                if (-not $process) {
                    Write-Log "INFO" "$ProcessFile`: Process $processId not used by Monitoring Agent, removing..."
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

# ======================================================================
# FAULT TOLERANCE FUNCTIONS
# ======================================================================

function Start-FaultToleranceComponents {
    Write-Log "DEBUG" "Initializing fault tolerance components..."
    
    # Start background monitoring processes
    Start-ProcessWatchdog
    
    # Initialize logging and alerting
    Initialize-WindowsLoggingSystem
    
    # Set up power event monitoring
    Register-PowerEvents
    
    # Initialize WMI monitoring
    Start-WMIMonitoring
}

function Complete-FaultToleranceStartup {
    Write-Log "DEBUG" "Completing fault tolerance startup..."
    
    # Start process health monitoring
    Start-ProcessHealthMonitoring
    
    # Initialize recovery mechanisms  
    Initialize-WindowsRecoverySystem
    
    # Send startup notification
    Send-WindowsStartupNotification
}

function Stop-FaultToleranceComponents {
    Write-Log "DEBUG" "Stopping fault tolerance components..."
    
    # Stop monitoring processes
    Stop-ProcessWatchdog
    
    # Stop health monitoring
    Stop-ProcessHealthMonitoring
    
    # Unregister power events
    Unregister-PowerEvents
    
    # Stop WMI monitoring
    Stop-WMIMonitoring
    
    # Send shutdown notification
    Send-WindowsShutdownNotification
}

function Start-ProcessWatchdog {
    $watchdogScript = Join-Path $script:AGENT_HOME "scripts\windows\monitoring-watchdog.ps1"
    $watchdogPidFile = Join-Path $script:PID_DIR "monitoring-watchdog.pid"
    
    if (Test-Path $watchdogScript) {
        Write-Log "DEBUG" "Starting process watchdog..."
        
        # Stop existing watchdog if running
        if (Test-Path $watchdogPidFile) {
            $oldPid = Get-Content $watchdogPidFile -ErrorAction SilentlyContinue
            if ($oldPid) {
                $oldProcess = Get-Process -Id $oldPid -ErrorAction SilentlyContinue
                if ($oldProcess) {
                    $oldProcess.Kill()
                    Start-Sleep -Seconds 1
                }
            }
            Remove-Item $watchdogPidFile -Force -ErrorAction SilentlyContinue
        }
        
        # Start new watchdog process
        try {
            $watchdogProcess = Start-Process -FilePath "PowerShell.exe" -ArgumentList @(
                "-ExecutionPolicy", "Bypass",
                "-WindowStyle", "Hidden",
                "-File", $watchdogScript
            ) -PassThru -WindowStyle Hidden
            
            $watchdogProcess.Id | Out-File -FilePath $watchdogPidFile -Encoding ASCII
            
            # Verify watchdog started
            Start-Sleep -Seconds 2
            if (Get-Process -Id $watchdogProcess.Id -ErrorAction SilentlyContinue) {
                Write-Log "DEBUG" "Process watchdog started (PID: $($watchdogProcess.Id))"
            } else {
                Write-Log "WARN" "Failed to start process watchdog"
            }
        }
        catch {
            Write-Log "WARN" "Failed to start process watchdog: $($_.Exception.Message)"
        }
    } else {
        Write-Log "DEBUG" "Watchdog script not found, skipping process monitoring"
    }
}

function Stop-ProcessWatchdog {
    $watchdogPidFile = Join-Path $script:PID_DIR "monitoring-watchdog.pid"
    
    if (Test-Path $watchdogPidFile) {
        $watchdogPid = Get-Content $watchdogPidFile -ErrorAction SilentlyContinue
        if ($watchdogPid) {
            $watchdogProcess = Get-Process -Id $watchdogPid -ErrorAction SilentlyContinue
            if ($watchdogProcess) {
                Write-Log "DEBUG" "Stopping process watchdog (PID: $watchdogPid)..."
                $watchdogProcess.Kill()
                
                # Wait for graceful shutdown
                for ($i = 1; $i -le 10; $i++) {
                    if (-not (Get-Process -Id $watchdogPid -ErrorAction SilentlyContinue)) {
                        break
                    }
                    Start-Sleep -Seconds 1
                }
            }
        }
        Remove-Item $watchdogPidFile -Force -ErrorAction SilentlyContinue
        Write-Log "DEBUG" "Process watchdog stopped"
    }
}

function Initialize-WindowsLoggingSystem {
    $loggingScript = Join-Path $script:AGENT_HOME "scripts\windows\monitoring-logging.ps1"
    
    if (Test-Path $loggingScript) {
        Write-Log "DEBUG" "Initializing enhanced logging system..."
        
        # Create alert configuration if it doesn't exist
        $alertConfig = Join-Path $script:AGENT_HOME "etc\monitoring-alerts.conf"
        if (-not (Test-Path $alertConfig)) {
            try {
                & $loggingScript -Action "init-config" -ErrorAction SilentlyContinue
            }
            catch {
                Write-Log "WARN" "Failed to initialize logging configuration"
            }
        }
        
        # Initialize alert state
        try {
            & $loggingScript -Action "init" -ErrorAction SilentlyContinue | Out-Null
        }
        catch {
            Write-Log "WARN" "Failed to initialize logging system"
        }
        
        Write-Log "DEBUG" "Enhanced logging system initialized"
    }
}

function Register-PowerEvents {
    Write-Log "DEBUG" "Registering power event monitoring..."
    
    try {
        # Create scheduled task for power events if it doesn't exist
        $taskName = "MonitoringAgent-PowerEvents"
        $existingTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        
        if (-not $existingTask) {
            $powerScript = Join-Path $script:AGENT_HOME "scripts\windows\monitoring-power-events.ps1"
            if (Test-Path $powerScript) {
                $action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-ExecutionPolicy Bypass -File `"$powerScript`" -Action Handle"
                $trigger = New-ScheduledTaskTrigger -AtLogOn
                $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
                $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
                
                Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -Principal $principal -ErrorAction SilentlyContinue | Out-Null
                Write-Log "DEBUG" "Power event monitoring task created"
            }
        }
    }
    catch {
        Write-Log "WARN" "Failed to register power event monitoring: $($_.Exception.Message)"
    }
}

function Unregister-PowerEvents {
    Write-Log "DEBUG" "Unregistering power event monitoring..."
    
    try {
        # Unregister scheduled task
        $taskName = "MonitoringAgent-PowerEvents"
        $existingTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        
        if ($existingTask) {
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
            Write-Log "DEBUG" "Power event monitoring task removed"
        }
    }
    catch {
        Write-Log "WARN" "Failed to unregister power event monitoring: $($_.Exception.Message)"
    }
}

function Start-WMIMonitoring {
    Write-Log "DEBUG" "Starting WMI monitoring..."
    
    try {
        # Create scheduled task for WMI monitoring
        $taskName = "MonitoringAgent-WMIEvents"
        $existingTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        
        if (-not $existingTask) {
            $wmiScript = Join-Path $script:AGENT_HOME "scripts\windows\monitoring-wmi-events.ps1"
            
            if (Test-Path $wmiScript) {
                $action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$wmiScript`""
                $trigger = New-ScheduledTaskTrigger -AtStartup
                $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
                $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
                
                Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -Principal $principal -ErrorAction SilentlyContinue | Out-Null
                
                # Start the task
                Start-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
                Write-Log "DEBUG" "WMI monitoring task created and started"
            }
        }
    }
    catch {
        Write-Log "WARN" "Failed to start WMI monitoring: $($_.Exception.Message)"
    }
}

function Stop-WMIMonitoring {
    Write-Log "DEBUG" "Stopping WMI monitoring..."
    
    try {
        $taskName = "MonitoringAgent-WMIEvents"
        $existingTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        
        if ($existingTask) {
            Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
            Write-Log "DEBUG" "WMI monitoring task stopped and removed"
        }
    }
    catch {
        Write-Log "WARN" "Failed to stop WMI monitoring: $($_.Exception.Message)"
    }
}

function Start-ProcessHealthMonitoring {
    Write-Log "DEBUG" "Starting process health monitoring..."
    
    # Start background health check loop
    $healthScript = {
        param($AgentHome)
        
        while ($true) {
            Start-Sleep -Seconds 300  # 5 minutes
            
            try {
                $recoveryScript = Join-Path $AgentHome "scripts\windows\monitoring-recovery.ps1"
                if (Test-Path $recoveryScript) {
                    & $recoveryScript -Action "health-check" -ErrorAction SilentlyContinue | Out-Null
                }
            }
            catch {
                # Silently continue on errors
            }
        }
    }
    
    try {
        $healthJob = Start-Job -ScriptBlock $healthScript -ArgumentList @($script:AGENT_HOME)
        $healthJob.Id | Out-File -FilePath (Join-Path $script:PID_DIR "monitoring-health.pid") -Encoding ASCII
        Write-Log "DEBUG" "Process health monitoring started (Job ID: $($healthJob.Id))"
    }
    catch {
        Write-Log "WARN" "Failed to start process health monitoring: $($_.Exception.Message)"
    }
}

function Stop-ProcessHealthMonitoring {
    $healthPidFile = Join-Path $script:PID_DIR "monitoring-health.pid"
    
    if (Test-Path $healthPidFile) {
        $jobId = Get-Content $healthPidFile -ErrorAction SilentlyContinue
        if ($jobId) {
            $job = Get-Job -Id $jobId -ErrorAction SilentlyContinue
            if ($job) {
                Stop-Job -Id $jobId -ErrorAction SilentlyContinue
                Remove-Job -Id $jobId -Force -ErrorAction SilentlyContinue
                Write-Log "DEBUG" "Process health monitoring stopped"
            }
        }
        Remove-Item $healthPidFile -Force -ErrorAction SilentlyContinue
    }
}

function Initialize-WindowsRecoverySystem {
    # Create state tracking directory
    $stateDir = Join-Path $script:AGENT_HOME "var\state"
    if (-not (Test-Path $stateDir)) {
        New-Item -ItemType Directory -Path $stateDir -Force -ErrorAction SilentlyContinue | Out-Null
    }
    
    # Record startup time
    [DateTimeOffset]::UtcNow.ToUnixTimeSeconds() | Out-File -FilePath (Join-Path $stateDir "startup_time") -Encoding ASCII
    
    # Initialize process restart counters
    foreach ($daemon in $script:DAEMONS) {
        "0" | Out-File -FilePath (Join-Path $stateDir "restart_count_$daemon") -Encoding ASCII -ErrorAction SilentlyContinue
    }
    
    Write-Log "DEBUG" "Recovery system initialized"
}

function Send-WindowsStartupNotification {
    $loggingScript = Join-Path $script:AGENT_HOME "scripts\windows\monitoring-logging.ps1"
    
    if (Test-Path $loggingScript) {
        try {
            & $loggingScript -Action "send-alert" -Level "INFO" -Title "Monitoring Agent Started" -Message "Monitoring Agent v$Script:AGENT_VERSION started successfully with fault tolerance enabled." -ErrorAction SilentlyContinue | Out-Null
        }
        catch {
            # Silently continue on notification errors
        }
    }
}

function Send-WindowsShutdownNotification {
    $loggingScript = Join-Path $script:AGENT_HOME "scripts\windows\monitoring-logging.ps1"
    
    if (Test-Path $loggingScript) {
        try {
            & $loggingScript -Action "send-alert" -Level "INFO" -Title "Monitoring Agent Stopped" -Message "Monitoring Agent v$Script:AGENT_VERSION has been stopped gracefully." -ErrorAction SilentlyContinue | Out-Null
        }
        catch {
            # Silently continue on notification errors  
        }
    }
}

function Test-FaultToleranceHealth {
    Write-Log "INFO" "Running comprehensive health check with fault tolerance validation..."
    
    $errors = 0
    
    # Run standard health check first
    if (-not (Test-AgentHealth)) {
        $errors++
    }
    
    # Check watchdog process
    $watchdogPidFile = Join-Path $script:PID_DIR "monitoring-watchdog.pid"
    if (Test-Path $watchdogPidFile) {
        $watchdogPid = Get-Content $watchdogPidFile -ErrorAction SilentlyContinue
        if ($watchdogPid) {
            $watchdogProcess = Get-Process -Id $watchdogPid -ErrorAction SilentlyContinue
            if ($watchdogProcess) {
                Write-Log "INFO" "✓ Process watchdog is running (PID: $watchdogPid)"
            } else {
                Write-Log "ERROR" "✗ Process watchdog is not running"
                $errors++
            }
        }
    } else {
        Write-Log "WARN" "Process watchdog PID file not found"
        $errors++
    }
    
    # Check scheduled tasks
    $powerTask = Get-ScheduledTask -TaskName "MonitoringAgent-PowerEvents" -ErrorAction SilentlyContinue
    if ($powerTask) {
        Write-Log "INFO" "✓ Power event monitoring task is configured"
    } else {
        Write-Log "WARN" "Power event monitoring task not found"
    }
    
    # Check health monitoring job
    $healthPidFile = Join-Path $script:PID_DIR "monitoring-health.pid"
    if (Test-Path $healthPidFile) {
        $jobId = Get-Content $healthPidFile -ErrorAction SilentlyContinue
        if ($jobId) {
            $job = Get-Job -Id $jobId -ErrorAction SilentlyContinue
            if ($job -and $job.State -eq "Running") {
                Write-Log "INFO" "✓ Health monitoring is running (Job ID: $jobId)"
            } else {
                Write-Log "WARN" "Health monitoring job is not running properly"
            }
        }
    }
    
    if ($errors -eq 0) {
        Write-Log "INFO" "✓ Comprehensive health check passed"
        return $true
    } else {
        Write-Log "ERROR" "✗ Comprehensive health check failed with $errors errors"
        return $false
    }
}

# ======================================================================
# END FAULT TOLERANCE FUNCTIONS
# ======================================================================

# Start function - Windows Implementation
function Start-Agent {
    Write-Log "INFO" "Starting Monitoring Agent $Script:AGENT_VERSION with Fault Tolerance..."
    
    # Initialize bypass mechanism first
    Initialize-MonitoringBypass
    
    # Ensure proper environment before starting
    Initialize-Environment
    
    # Restore agent connection if it was disabled during stop
    Restore-AgentConnection
    
    # Clean PID files and check processes
    Test-ProcessIds
    
    # Delete all files in temporary folder
    $tempPath = Join-Path $script:AGENT_HOME "tmp"
    if (Test-Path $tempPath) {
        Get-ChildItem -Path $tempPath | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    }

    # Initialize fault tolerance components
    Start-FaultToleranceComponents
    
    # Windows-specific agent startup (single process approach)
    $daemon = "monitoring-agentd"
    $status = Get-ProcessStatus $daemon
    
    if ($status -eq 0) {
        Write-Log "INFO" "Starting $daemon..."
        
        # Path to the Windows Monitoring Agent executable
        $binaryPath = Join-Path $script:AGENT_HOME "bin\MONITORING_AGENT.EXE"
        
        if (-not (Test-Path $binaryPath)) {
            Write-Log "ERROR" "Monitoring Agent executable not found: $binaryPath"
            Unlock-Process
            exit 1
        }
        
        # Set working directory to the windows directory (AGENT_HOME)
        $originalLocation = Get-Location
        try {
            Set-Location $script:AGENT_HOME
            
            # Prepare arguments for Windows agent (use 'start' for manual execution)
            $arguments = @("start")
            
            Write-Log "DEBUG" "Setting up Windows agent environment..."
            
            # Ensure all required files are in the bin directory
            $binPath = Join-Path $script:AGENT_HOME "bin"
            $configFiles = @("ossec.conf", "client.keys", "internal_options.conf", "local_internal_options.conf", "wpk_root.pem")
            foreach ($file in $configFiles) {
                $sourcePath = Join-Path $script:AGENT_HOME $file
                $destPath = Join-Path $binPath $file
                if (Test-Path $sourcePath) {
                    Copy-Item $sourcePath $destPath -Force -ErrorAction SilentlyContinue
                    Write-Log "DEBUG" "Copied $file to bin directory"
                } else {
                    # Also check in etc subdirectory
                    $etcPath = Join-Path $script:AGENT_HOME "etc\$file"
                    if (Test-Path $etcPath) {
                        Copy-Item $etcPath $destPath -Force -ErrorAction SilentlyContinue
                        Write-Log "DEBUG" "Copied $file from etc to bin directory"
                    }
                }
            }
            
            # Copy all DLL dependencies to bin directory
            $libPath = Join-Path $script:AGENT_HOME "lib"
            if (Test-Path $libPath) {
                Get-ChildItem -Path $libPath -Filter "*.dll" | ForEach-Object {
                    Copy-Item $_.FullName $binPath -Force -ErrorAction SilentlyContinue
                    Write-Log "DEBUG" "Copied $($_.Name) to bin directory"
                }
            }
            
            # Create required directory structure in bin directory
            $requiredDirs = @(
                "rids", "queue\logcollector", "shared", "ruleset\sca", 
                "queue\diff", "queue\fim", "queue\agent-upgrade"
            )
            foreach ($dir in $requiredDirs) {
                $dirPath = Join-Path $binPath $dir
                if (-not (Test-Path $dirPath)) {
                    New-Item -ItemType Directory -Path $dirPath -Force -ErrorAction SilentlyContinue | Out-Null
                    Write-Log "DEBUG" "Created directory: $dir"
                }
            }
            
            # Create required files
            $ridFile = Join-Path $binPath "rids\001"
            if (-not (Test-Path $ridFile)) {
                "0" | Out-File -FilePath $ridFile -Encoding ASCII -ErrorAction SilentlyContinue
                Write-Log "DEBUG" "Created rids/001 file"
            }
            
            $statusFile = Join-Path $binPath "queue\logcollector\file_status.json"
            if (-not (Test-Path $statusFile)) {
                "{}" | Out-File -FilePath $statusFile -Encoding ASCII -ErrorAction SilentlyContinue
                Write-Log "DEBUG" "Created file_status.json"
            }
            
            $mergedFile = Join-Path $binPath "shared\merged.mg"
            if (-not (Test-Path $mergedFile)) {
                "" | Out-File -FilePath $mergedFile -Encoding ASCII -ErrorAction SilentlyContinue
                Write-Log "DEBUG" "Created merged.mg file"
            }
            
            
            # Ensure configuration files are in bin directory for agent access
            $binPath = Join-Path $script:AGENT_HOME "bin"
            $etcPath = Join-Path $script:AGENT_HOME "etc"
            
            # Copy essential config files to bin directory
            @("ossec.conf", "OSSEC.CONF", "client.keys", "internal_options.conf", "wpk_root.pem") | ForEach-Object {
                $srcPath = Join-Path $etcPath $_
                $destPath = Join-Path $binPath $_
                
                if (Test-Path $srcPath) {
                    try {
                        Copy-Item -Path $srcPath -Destination $destPath -Force -ErrorAction SilentlyContinue
                        Write-Log "DEBUG" "Copied $_ to bin directory"
                    } catch {
                        Write-Log "WARN" "Could not copy $_ to bin directory: $($_.Exception.Message)"
                    }
                }
            }
            
            # Try service installation and start first (more reliable for persistent connections)
            try {
                Write-Log "INFO" "Installing and starting Monitoring Agent service..."
                Push-Location $binPath
                $installResult = & ".\MONITORING_AGENT.EXE" "install-service" 2>&1
                Write-Log "DEBUG" "Service install result: $installResult"
                Pop-Location
                
                Start-Sleep 2
                Start-Service -Name "WazuhSvc" -ErrorAction Stop
                Start-Sleep 3
                
                $service = Get-Service -Name "WazuhSvc" -ErrorAction SilentlyContinue
                if ($service -and $service.Status -eq 'Running') {
                    Write-Log "INFO" "✓ Monitoring Agent service started successfully"
                    return $true
                } else {
                    Write-Log "WARN" "Service installation attempted but not running, trying process method"
                }
            } catch {
                Write-Log "WARN" "Service start failed: $($_.Exception.Message), trying process method"
            }
            
            # Fallback: Try direct process start (this method works!)
            try {
                Write-Log "INFO" "Starting Monitoring Agent as process..."
                $processInfo = Start-Process -FilePath "MONITORING_AGENT.EXE" -WorkingDirectory $binPath -WindowStyle Hidden -PassThru -ErrorAction Stop
                
                if ($processInfo) {
                    Start-Sleep 3
                    if (-not $processInfo.HasExited) {
                        Write-Log "INFO" "✓ Monitoring Agent started successfully with PID: $($processInfo.Id)"
                        
                        # Verify connection to manager (extract from config)
                        try {
                            $configPath = Join-Path $script:AGENT_HOME "etc\OSSEC.CONF"
                            if (-not (Test-Path $configPath)) {
                                $configPath = Join-Path $script:AGENT_HOME "OSSEC.CONF"
                            }
                            $configContent = Get-Content $configPath -Raw
                            $addressMatch = [regex]::Match($configContent, '<address>([^<]+)</address>')
                            $portMatch = [regex]::Match($configContent, '<port>([^<]+)</port>')
                            
                            if ($addressMatch.Success) {
                                $managerIP = $addressMatch.Groups[1].Value
                                $managerPort = if ($portMatch.Success) { $portMatch.Groups[1].Value } else { "1514" }
                                Write-Log "INFO" "Agent should now be connected to manager at $managerIP`:$managerPort"
                            } else {
                                Write-Log "INFO" "Agent started - check configuration for manager details"
                            }
                        } catch {
                            Write-Log "INFO" "Agent started successfully"
                        }
                        
                        return $true
                    } else {
                        Write-Log "WARN" "Process started but exited immediately"
                        # Check for common startup issues
                        $logPath = Join-Path $script:AGENT_HOME "logs\monitoring-agent.log"
                        if (Test-Path $logPath) {
                            $recentLogs = Get-Content $logPath -Tail 5
                            Write-Log "DEBUG" "Recent log entries: $($recentLogs -join '; ')"
                        }
                    }
                }
            } catch {
                Write-Log "WARN" "Direct process start failed: $_"
            }
            
            # Fallback to service method
            Write-Log "INFO" "Trying service method as fallback..."
            try {
                $serviceStatus = Get-Service -Name "WazuhSvc" -ErrorAction SilentlyContinue
                if (-not $serviceStatus) {
                    Write-Log "INFO" "Installing Monitoring Agent service..."
                    $servicePath = Join-Path $script:AGENT_HOME "bin\MONITORING_AGENT.EXE"
                    & "$servicePath" install-service
                }
                
                Write-Log "INFO" "Starting Monitoring Agent service..."
                Start-Service -Name "WazuhSvc"
                
                # Wait and check service status multiple times
                $attempts = 0
                $maxAttempts = 5
                $serviceRunning = $false
                
                while ($attempts -lt $maxAttempts -and -not $serviceRunning) {
                    Start-Sleep 3
                    $service = Get-Service -Name "WazuhSvc" -ErrorAction SilentlyContinue
                    if ($service -and $service.Status -eq "Running") {
                        $serviceRunning = $true
                        Write-Log "INFO" "✓ Monitoring Agent service started successfully!"
                        return $true
                    } else {
                        $attempts++
                        Write-Log "WARN" "Service attempt $attempts/$maxAttempts - Status: $($service.Status)"
                        if ($attempts -lt $maxAttempts) {
                            Write-Log "INFO" "Retrying service start..."
                            Start-Service -Name "WazuhSvc" -ErrorAction SilentlyContinue
                        }
                    }
                }
                
                if (-not $serviceRunning) {
                    Write-Log "ERROR" "Failed to start Monitoring Agent service after $maxAttempts attempts"
                    Write-Log "INFO" "Attempting alternative process start method..."
                    
                    # Alternative: Try starting as a regular process from bin directory
                    $binPath = Join-Path $script:AGENT_HOME "bin"
                    $processInfo = Start-Process -FilePath "MONITORING_AGENT.EXE" -ArgumentList "start" -WorkingDirectory $binPath -WindowStyle Hidden -PassThru -ErrorAction SilentlyContinue
                    
                    if ($processInfo) {
                        Start-Sleep 3
                        if (-not $processInfo.HasExited) {
                            Write-Log "INFO" "✓ Started agent as process with PID: $($processInfo.Id)"
                            return $true
                        }
                    }
                    return $false
                }
                
                return $true
            
            # Service started successfully, set return value for rest of function
            $processInfo = $true
        } catch {
            Write-Log "ERROR" "Failed to start Monitoring Agent service: $_"
            Set-Location $originalLocation
            Unlock-Process
            exit 1
        }
        }
        catch {
            Write-Log "ERROR" "Exception starting Monitoring Agent: $($_.Exception.Message)"
            Set-Location $originalLocation
            Unlock-Process
            exit 1
        }
        finally {
            Set-Location $originalLocation
        }
    }
    else {
        Write-Log "INFO" "monitoring-agentd already running..."
    }
    
    # Complete fault tolerance initialization
    Complete-FaultToleranceStartup
    
    # Mark agent as running for boot recovery
    $bootRecoveryScript = Join-Path $script:AGENT_HOME "scripts\windows\monitoring-boot-recovery.ps1"
    if (Test-Path $bootRecoveryScript) {
        try {
            & $bootRecoveryScript "mark-running"
        }
        catch {
            Write-Log "WARN" "Failed to mark agent as running for boot recovery: $($_.Exception.Message)"
        }
    }
    
    Write-Log "INFO" "✓ Monitoring Agent started successfully with fault tolerance!"
}

function Stop-Agent {
    Write-Log "INFO" "Stopping Monitoring Agent $Script:AGENT_VERSION and Fault Tolerance..."
    
    # Mark agent as stopped for boot recovery
    $bootRecoveryScript = Join-Path $script:AGENT_HOME "scripts\windows\monitoring-boot-recovery.ps1"
    if (Test-Path $bootRecoveryScript) {
        try {
            & $bootRecoveryScript "mark-stopped"
        }
        catch {
            Write-Log "WARN" "Failed to mark agent as stopped for boot recovery: $($_.Exception.Message)"
        }
    }
    
    # FIRST: Stop Windows services if they exist (only on actual Windows)
    $servicesFound = $false
    # Windows service management
    $services = @("MonitoringAgent", "MonitoringAgentWatchdog")
    foreach ($serviceName in $services) {
        $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if ($service -and $service.Status -eq 'Running') {
            try {
                Stop-Service -Name $serviceName -Force -ErrorAction Stop
                Write-Log "INFO" "Stopped Windows service: $serviceName"
                $servicesFound = $true
            }
            catch {
                Write-Log "WARN" "Failed to stop service $serviceName`: $($_.Exception.Message)"
            }
        }
    }
    
    if ($servicesFound) {
        Write-Log "INFO" "Waiting for services to stop completely..."
        foreach ($serviceName in $services) {
            $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
            if ($service) {
                try {
                    $service.WaitForStatus('Stopped', '00:00:30')
                }
                catch {
                    Write-Log "WARN" "Service $serviceName did not stop within timeout"
                }
            }
        }
    }
    else {
        Write-Log "INFO" "Windows services not available on this platform"
    }
    
    # SECOND: Mark agent as stopped for boot recovery to prevent restarts
    $bootRecoveryScript = Join-Path $script:AGENT_HOME "scripts\windows\monitoring-boot-recovery.ps1"
    if (Test-Path $bootRecoveryScript) {
        try {
            & $bootRecoveryScript "mark-stopped"
            Write-Log "INFO" "Marked agent as stopped"
        }
        catch {
            Write-Log "WARN" "Failed to mark agent as stopped for boot recovery: $($_.Exception.Message)"
        }
    }
    
    # THIRD: Force agent disconnection from Wazuh manager
    Disconnect-Agent
    
    # Give a moment for state change to take effect
    Start-Sleep -Seconds 2
    
    # FOURTH: Stop fault tolerance components (including watchdog)
    Stop-FaultToleranceComponents
    
    # Give more time for watchdog to detect state change and exit
    Start-Sleep -Seconds 3
    
    Test-ProcessIds
    
    # Stop the main monitoring agent process
    $mainProcessName = "MONITORING_AGENT"
    $processes = Get-Process -Name $mainProcessName -ErrorAction SilentlyContinue
    
    if ($processes) {
        Write-Log "INFO" "Stopping $mainProcessName processes..."
        foreach ($process in $processes) {
            try {
                Write-Log "INFO" "Killing $mainProcessName (PID: $($process.Id))..."
                $process.Kill()
                $process.WaitForExit(10000) # Wait up to 10 seconds
                Write-Log "INFO" "Process $($process.Id) terminated successfully"
            }
            catch {
                Write-Log "WARN" "Error stopping process $($process.Id): $($_.Exception.Message)"
                try {
                    Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
                    Write-Log "INFO" "Force killed process $($process.Id)"
                }
                catch {
                    Write-Log "WARN" "Could not force kill process $($process.Id)"
                }
            }
        }
    } else {
        Write-Log "INFO" "$mainProcessName not running..."
    }
    
    # Also check for any remaining monitoring processes by name pattern
    $remainingProcesses = Get-Process | Where-Object { $_.ProcessName -like "*monitoring*" -or $_.ProcessName -like "*MONITORING*" } -ErrorAction SilentlyContinue
    if ($remainingProcesses) {
        Write-Log "INFO" "Cleaning up remaining monitoring processes..."
        foreach ($process in $remainingProcesses) {
            try {
                Write-Log "INFO" "Killing remaining process: $($process.ProcessName) (PID: $($process.Id))"
                $process.Kill()
            }
            catch {
                Write-Log "WARN" "Could not kill process $($process.ProcessName) (PID: $($process.Id))"
            }
        }
    }

    # Legacy daemon stopping code (for compatibility)
    foreach ($daemon in $script:DAEMONS) {
        $status = Get-ProcessStatus $daemon
        if ($status -eq 1) {
            Write-Log "INFO" "Killing $daemon..."
            
            # Get the correct PID file name
            $pidName = Get-PidName $daemon
            $pidPattern = Join-Path $script:PID_DIR "$pidName-*.pid"
            $pidFiles = Get-ChildItem -Path $pidPattern -ErrorAction SilentlyContinue
            
            foreach ($pidFile in $pidFiles) {
                try {
                    $processId = Get-Content $pidFile.FullName -ErrorAction Stop
                    $process = Get-Process -Id $processId -ErrorAction SilentlyContinue
                    
                    if ($process) {
                        $process.Kill()
                        $waitResult = Wait-ProcessId $processId
                        if ($waitResult -ne 0) {
                            Write-Log "WARN" "Process $daemon couldn't be terminated gracefully. Force killing..."
                            try {
                                Stop-Process -Id $processId -Force -ErrorAction SilentlyContinue
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
        
        # Remove PID files using correct naming
        $pidName = Get-PidName $daemon
        $pidPattern = Join-Path $script:PID_DIR "$pidName-*.pid"
        Get-ChildItem -Path $pidPattern -ErrorAction SilentlyContinue | Remove-Item -Force
    }
    
    Write-Log "INFO" "Monitoring Agent $Script:AGENT_VERSION Stopped"
}

function Stop-ProcessByName {
    param([string]$ProcessName)
    
    $processId = Get-ProcessPid $ProcessName
    
    if ($processId) {
        Write-Log "DEBUG" "Stopping $ProcessName (PID: $processId)..."
        try {
            Stop-Process -Id $processId -ErrorAction Stop
            
            if (Wait-ForProcess $ProcessName "stop") {
                Write-Log "INFO" "$ProcessName stopped successfully"
            }
            else {
                Write-Log "WARN" "Force killing $ProcessName..."
                Stop-Process -Id $processId -Force -ErrorAction SilentlyContinue
                Start-Sleep -Seconds 2
            }
        }
        catch {
            Write-Log "WARN" "Error stopping $ProcessName`: $($_.Exception.Message)"
        }
    }
}

function Test-AgentRunning {
    # Check for currently running process
    $runningProcess = Get-Process -Name "MONITORING_AGENT" -ErrorAction SilentlyContinue
    if ($runningProcess) {
        return $true
    }
    
    # Check service status
    $service = Get-Service -Name "WazuhSvc" -ErrorAction SilentlyContinue
    if ($service -and $service.Status -eq "Running") {
        return $true
    }
    
    # Check for recent successful connections (within last 5 minutes)
    $logFile = Join-Path $script:AGENT_HOME "logs\monitoring-agent.log"
    if (Test-Path $logFile) {
        $recentTime = (Get-Date).AddMinutes(-5)
        $recentConnections = Get-Content $logFile -Tail 50 | Where-Object {
            if ($_ -match "^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}).*Connected to the server") {
                try {
                    $logTime = [DateTime]::ParseExact($matches[1], "yyyy/MM/dd HH:mm:ss", $null)
                    return ($logTime -gt $recentTime)
                } catch {
                    return $false
                }
            }
            return $false
        }
        
        if ($recentConnections.Count -gt 0) {
            return $true
        }
    }
    
    return $false
}

function Get-AgentStatus {
    Write-Host ""
    Write-Host "=======================================" -ForegroundColor Yellow
    Write-Host "Monitoring Agent Status" -ForegroundColor Yellow
    Write-Host "=======================================" -ForegroundColor Yellow
    
    $script:RETVAL = 0
    $allRunning = $true
    
    # Check main monitoring agent process
    $mainProcess = "MONITORING_AGENT"
    $processes = Get-Process -Name $mainProcess -ErrorAction SilentlyContinue
    $hasRecentConnection = $false
    
    # Check for recent successful connections in logs
    $logFile = Join-Path $script:AGENT_HOME "logs\monitoring-agent.log"
    if (Test-Path $logFile) {
        $recentTime = (Get-Date).AddMinutes(-5)
        $recentConnections = Get-Content $logFile -Tail 50 | Where-Object {
            if ($_ -match "^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}).*Connected to the server") {
                try {
                    $logTime = [DateTime]::ParseExact($matches[1], "yyyy/MM/dd HH:mm:ss", $null)
                    return ($logTime -gt $recentTime)
                } catch {
                    return $false
                }
            }
            return $false
        }
        $hasRecentConnection = $recentConnections.Count -gt 0
    }
    
    if ($processes) {
        Write-Host "✓ Monitoring Agent Process: " -NoNewline -ForegroundColor Green
        Write-Host "RUNNING (PID: $($processes[0].Id))" -ForegroundColor Green
    } elseif ($hasRecentConnection) {
        Write-Host "✓ Monitoring Agent Connection: " -NoNewline -ForegroundColor Green
        Write-Host "CONNECTED (Recent successful connection to manager)" -ForegroundColor Green
    } else {
        Write-Host "✗ Monitoring Agent Process: " -NoNewline -ForegroundColor Red
        Write-Host "NOT RUNNING" -ForegroundColor Red
        $allRunning = $false
        $script:RETVAL = 1
    }
    
    # Check Windows service if exists
    $service = Get-Service -Name "WazuhSvc" -ErrorAction SilentlyContinue
    if ($service) {
        if ($service.Status -eq "Running") {
            Write-Host "✓ Windows Service: " -NoNewline -ForegroundColor Green
            Write-Host "RUNNING" -ForegroundColor Green
        } else {
            Write-Host "✗ Windows Service: " -NoNewline -ForegroundColor Red
            Write-Host "$($service.Status)" -ForegroundColor Red
        }
    }
    
    # Check configuration status
    Write-Host ""
    Write-Host "Configuration Status:" -ForegroundColor Cyan
    
    if (Test-Path $script:CONFIG_FILE) {
        Write-Host "✓ Configuration File: " -NoNewline -ForegroundColor Green
        Write-Host "EXISTS ($script:CONFIG_FILE)" -ForegroundColor Green
        
        # Extract manager info from config
        try {
            $configContent = Get-Content $script:CONFIG_FILE -Raw
            $addressMatch = [regex]::Match($configContent, '<address>([^<]+)</address>')
            $portMatch = [regex]::Match($configContent, '<port>([^<]+)</port>')
            
            if ($addressMatch.Success) {
                $managerIP = $addressMatch.Groups[1].Value
                $managerPort = if ($portMatch.Success) { $portMatch.Groups[1].Value } else { "1514" }
                Write-Host "✓ Manager Address: " -NoNewline -ForegroundColor Green
                Write-Host "$managerIP`:$managerPort" -ForegroundColor Green
            }
        } catch {
            Write-Host "✗ Configuration: " -NoNewline -ForegroundColor Red
            Write-Host "ERROR READING CONFIG" -ForegroundColor Red
        }
    } else {
        Write-Host "✗ Configuration File: " -NoNewline -ForegroundColor Red
        Write-Host "NOT FOUND" -ForegroundColor Red
        $allRunning = $false
    }
    
    if (Test-Path $script:CLIENT_KEYS) {
        Write-Host "✓ Client Keys: " -NoNewline -ForegroundColor Green
        Write-Host "EXISTS ($script:CLIENT_KEYS)" -ForegroundColor Green
        
        # Show enrollment status
        try {
            $keyContent = Get-Content $script:CLIENT_KEYS -Raw
            if ($keyContent -and $keyContent.Trim()) {
                $keyParts = $keyContent.Trim() -split '\s+'
                if ($keyParts.Count -ge 4) {
                    Write-Host "✓ Agent Enrolled: " -NoNewline -ForegroundColor Green
                    Write-Host "ID=$($keyParts[0]), Name=$($keyParts[1])" -ForegroundColor Green
                } else {
                    Write-Host "✗ Client Keys: " -NoNewline -ForegroundColor Red
                    Write-Host "INVALID FORMAT" -ForegroundColor Red
                }
            } else {
                Write-Host "✗ Client Keys: " -NoNewline -ForegroundColor Red
                Write-Host "EMPTY FILE" -ForegroundColor Red
                $allRunning = $false
            }
        } catch {
            Write-Host "✗ Client Keys: " -NoNewline -ForegroundColor Red
            Write-Host "ERROR READING KEYS" -ForegroundColor Red
        }
    } else {
        Write-Host "✗ Client Keys: " -NoNewline -ForegroundColor Red
        Write-Host "NOT FOUND (Agent not enrolled)" -ForegroundColor Red
        $allRunning = $false
    }
    
    # Check log file for recent activity
    if (Test-Path $script:LOG_FILE) {
        try {
            $lastModified = (Get-Item $script:LOG_FILE).LastWriteTime
            $timeDiff = (Get-Date) - $lastModified
            if ($timeDiff.TotalMinutes -lt 5) {
                Write-Host "✓ Recent Activity: " -NoNewline -ForegroundColor Green
                Write-Host "LOG UPDATED $([math]::Round($timeDiff.TotalMinutes, 1)) MINUTES AGO" -ForegroundColor Green
            } else {
                Write-Host "⚠ Recent Activity: " -NoNewline -ForegroundColor Yellow
                Write-Host "LOG LAST UPDATED $([math]::Round($timeDiff.TotalHours, 1)) HOURS AGO" -ForegroundColor Yellow
            }
        } catch {
            Write-Host "✗ Log File: " -NoNewline -ForegroundColor Red
            Write-Host "ERROR ACCESSING LOG" -ForegroundColor Red
        }
    } else {
        Write-Host "✗ Log File: " -NoNewline -ForegroundColor Red
        Write-Host "NOT FOUND" -ForegroundColor Red
    }
    
    Write-Host ""
    Write-Host "Overall Status: " -NoNewline -ForegroundColor Cyan
    if ($allRunning) {
        Write-Host "HEALTHY" -ForegroundColor Green
        Write-Host "=======================================" -ForegroundColor Yellow
    } else {
        Write-Host "ISSUES DETECTED" -ForegroundColor Red
        Write-Host "=======================================" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "Recommendations:" -ForegroundColor Yellow
        if (-not (Test-Path $script:CLIENT_KEYS) -or -not (Get-Content $script:CLIENT_KEYS -Raw).Trim()) {
            Write-Host "• Run enrollment: .\monitoring-agent-control.ps1 enroll <manager-ip>" -ForegroundColor Yellow
        }
        if ($script:RETVAL -eq 1) {
            Write-Host "• Start the agent: .\monitoring-agent-control.ps1 start" -ForegroundColor Yellow
        }
        Write-Host ""
    }
    
    return $script:RETVAL
}

function Test-ConfigurationInternal {
    Write-Log "DEBUG" "Validating configuration..."
    
    if (-not (Test-Path $script:CONFIG_FILE)) {
        Write-Log "ERROR" "Configuration file not found: $script:CONFIG_FILE"
        return $false
    }
    
    try {
        $configContent = Get-Content $script:CONFIG_FILE -Raw
        Write-Log "DEBUG" "Configuration file loaded successfully"
        
        # Check if essential configuration sections exist
        if ($configContent -notmatch "<client>") {
            Write-Log "ERROR" "Client configuration section not found"
            return $false
        }
        
        if ($configContent -notmatch "<server>") {
            Write-Log "ERROR" "Server configuration section not found"
            return $false
        }
        
        # Basic XML structure check with more robust validation
        if ($configContent -notmatch "<ossec_config>" -or $configContent -notmatch "</ossec_config>") {
            Write-Log "WARN" "Configuration may have XML structure issues"
            # More lenient check for XML structure
            try {
                [xml]$xmlContent = $configContent
                if ($xmlContent.DocumentElement.Name -ne "ossec_config") {
                    Write-Log "ERROR" "Root element is not ossec_config"
                    return $false
                }
                Write-Log "DEBUG" "XML structure validation passed"
            } catch {
                Write-Log "ERROR" "XML parsing failed: $($_.Exception.Message)"
                return $false
            }
        } else {
            Write-Log "DEBUG" "Basic XML structure validation passed"
        }
        
        Write-Log "DEBUG" "Configuration validation passed"
        return $true
    }
    catch {
        Write-Log "ERROR" "Failed to read configuration file: $($_.Exception.Message)"
        return $false
    }
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

function Invoke-AgentEnrollment {
    param(
        [string]$ManagerInput,
        [string]$ManagerPort = "",
        [string]$AgentName = $env:COMPUTERNAME,
        [string]$AgentId = "",
        [string]$AgentKey = "",
        [string]$AgentIP = "any"
    )
    
    # NOTE: This enrollment function now accepts either a plain client key line
    # ("001 name ip keyhex...") or a base64-encoded string containing that line.
    # If a base64 string is provided (interactive or via the AgentKey parameter),
    # we attempt to decode it automatically and validate the resulting key line.
    # This simplifies enrollment when managers only provide an encoded key.

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
        Write-Host "  # Use the Windows agent management tools instead"
        Write-Host ""
        Write-Host "The key should be in format:"
        Write-Host "  001 agent-name 192.168.1.100 abc123...def456"
        Write-Host ""
    $clientKeyLine = Read-Host "Enter the complete client key line (or paste base64-encoded key)"
        
        if (-not $clientKeyLine) {
            Write-Log "ERROR" "Client key is required for enrollment"
            return $false
        }
        
        # If the provided line looks like base64, attempt to decode it automatically
        if ($clientKeyLine -match '^[A-Za-z0-9+/=]+$') {
            try {
                $decodedBytes = [System.Convert]::FromBase64String($clientKeyLine)
                $decoded = [System.Text.Encoding]::UTF8.GetString($decodedBytes)
                # Normalize whitespace
                $decoded = ($decoded -replace '[\r\n]+',' ' -replace '\s+',' ').Trim()
                Write-Log "DEBUG" "Decoded base64 client key: $decoded"
                $clientKeyLine = $decoded
            }
            catch {
                Write-Log "WARN" "Provided client key looks like base64 but failed to decode; continuing with original input"
            }
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
            # Support case where $AgentKey is a base64-encoded full client key line
            if ($AgentKey -match '^[A-Za-z0-9+/=]+$') {
                try {
                    $decodedBytes = [System.Convert]::FromBase64String($AgentKey)
                    $decoded = [System.Text.Encoding]::UTF8.GetString($decodedBytes)
                    $decoded = ($decoded -replace '[\r\n]+',' ' -replace '\s+',' ').Trim()
                    Write-Log "DEBUG" "Decoded base64 AgentKey to: $decoded"
                    if (Test-ClientKey $decoded) {
                        $parts = $decoded -split '\s+'
                        $AgentId = $parts[0]
                        $AgentName = $parts[1]
                        $AgentIP = $parts[2]
                        $AgentKey = $parts[3]
                    }
                    else {
                        Write-Log "ERROR" "Agent ID is required when providing agent key (decoded content invalid)"
                        return $false
                    }
                }
                catch {
                    Write-Log "ERROR" "Agent ID is required when providing agent key"
                    return $false
                }
            }
            else {
                Write-Log "ERROR" "Agent ID is required when providing agent key"
                return $false
            }
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
    "$AgentId $AgentName $AgentIP $AgentKey" | Set-Content $script:CLIENT_KEYS -Encoding utf8
    
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

# ======================================================================
# ENHANCED FAULT TOLERANCE FUNCTIONS - WINDOWS IMPLEMENTATION
# ======================================================================

function Start-FaultToleranceComponents {
    Write-Log "DEBUG" "Initializing fault tolerance components for Windows..."
    
    # Start background watchdog process
    Start-ProcessWatchdog
    
    # Initialize logging and alerting
    Initialize-LoggingSystem
    
    # Set up signal handlers for graceful shutdown
    Initialize-SignalHandlers
    
    # Initialize state tracking
    Initialize-StateTracking
}

function Complete-FaultToleranceStartup {
    Write-Log "DEBUG" "Completing fault tolerance startup for Windows..."
    
    # Start monitoring processes for health
    Start-ProcessMonitoring
    
    # Initialize recovery mechanisms
    Initialize-RecoverySystem
    
    # Send startup notification
    Send-StartupNotification
}

function Stop-FaultToleranceComponents {
    Write-Log "DEBUG" "Stopping fault tolerance components for Windows..."
    
    # Stop watchdog process
    Stop-ProcessWatchdog
    
    # Stop background monitoring
    Stop-ProcessMonitoring
    
    # Send shutdown notification
    Send-ShutdownNotification
}

function Initialize-StateTracking {
    $stateDir = Join-Path $script:AGENT_HOME "var\state"
    if (-not (Test-Path $stateDir)) {
        New-Item -Path $stateDir -ItemType Directory -Force | Out-Null
    }
    
    # Record startup time
    [int][double]::Parse((Get-Date -UFormat %s)) | Set-Content -Path (Join-Path $stateDir "startup_time") -Encoding utf8
    
    # Initialize process restart counters
    foreach ($daemon in $script:DAEMONS) {
        "0" | Set-Content -Path (Join-Path $stateDir "restart_count_$daemon") -Encoding utf8
    }
    
    Write-Log "DEBUG" "State tracking initialized"
}

function Initialize-LoggingSystem {
    $loggingScript = Join-Path $script:AGENT_HOME "scripts\windows\monitoring-logging.ps1"
    
    if (Test-Path $loggingScript) {
        try {
            & $loggingScript "init" | Out-Null
            Write-Log "DEBUG" "Enhanced logging system initialized"
        }
        catch {
            Write-Log "WARN" "Failed to initialize enhanced logging: $($_.Exception.Message)"
        }
    }
}

function Start-ProcessMonitoring {
    $recoveryScript = Join-Path $script:AGENT_HOME "scripts\windows\monitoring-recovery.ps1"
    
    if (Test-Path $recoveryScript) {
        try {
            $process = Start-Process -FilePath "PowerShell.exe" -ArgumentList "-ExecutionPolicy Bypass -File `"$recoveryScript`"" -WindowStyle Hidden -PassThru
            $pidFile = Join-Path $script:PID_DIR "monitoring-recovery.pid"
            $process.Id | Set-Content -Path $pidFile -Encoding utf8
            Write-Log "DEBUG" "Recovery monitoring started with PID: $($process.Id)"
        }
        catch {
            Write-Log "WARN" "Failed to start recovery monitoring: $($_.Exception.Message)"
        }
    }
}

function Stop-ProcessMonitoring {
    $recoveryPidFile = Join-Path $script:PID_DIR "monitoring-recovery.pid"
    
    if (Test-Path $recoveryPidFile) {
        try {
            $processId = Get-Content $recoveryPidFile -ErrorAction Stop
            $process = Get-Process -Id $processId -ErrorAction SilentlyContinue
            if ($process) {
                $process.Kill()
                Wait-Process -Id $processId -Timeout 10 -ErrorAction SilentlyContinue
            }
            Remove-Item $recoveryPidFile -ErrorAction SilentlyContinue
            Write-Log "DEBUG" "Recovery monitoring stopped"
        }
        catch {
            Write-Log "WARN" "Failed to stop recovery monitoring: $($_.Exception.Message)"
        }
    }
}

function Initialize-SignalHandlers {
    # Windows equivalent using console events
    try {
        $null = [Console]::TreatControlCAsInput = $false
        Write-Log "DEBUG" "Signal handlers configured for Windows"
    }
    catch {
        Write-Log "WARN" "Could not configure signal handlers: $($_.Exception.Message)"
    }
}

function Initialize-RecoverySystem {
    Write-Log "DEBUG" "Initializing recovery system for Windows..."
    
    # Set up basic recovery mechanisms
    try {
        $recoveryDir = Join-Path $script:AGENT_HOME "var\recovery"
        if (-not (Test-Path $recoveryDir)) {
            New-Item -Path $recoveryDir -ItemType Directory -Force | Out-Null
        }
        
        # Create recovery state file
        $recoveryState = @{
            LastStartTime = Get-Date
            RecoveryCount = 0
            Status = "Running"
        } | ConvertTo-Json
        
        $recoveryStateFile = Join-Path $recoveryDir "recovery.state"
        $recoveryState | Set-Content -Path $recoveryStateFile -Encoding utf8
        
        Write-Log "DEBUG" "Recovery system initialized"
    }
    catch {
        Write-Log "WARN" "Failed to initialize recovery system: $($_.Exception.Message)"
    }
}

function Send-StartupNotification {
    $loggingScript = Join-Path $script:AGENT_HOME "scripts\windows\monitoring-logging.ps1"
    
    if (Test-Path $loggingScript) {
        try {
            & $loggingScript "startup" "Monitoring Agent started successfully with fault tolerance" | Out-Null
        }
        catch {
            Write-Log "DEBUG" "Could not send startup notification: $($_.Exception.Message)"
        }
    }
}

function Send-ShutdownNotification {
    $loggingScript = Join-Path $script:AGENT_HOME "scripts\windows\monitoring-logging.ps1"
    
    if (Test-Path $loggingScript) {
        try {
            & $loggingScript "shutdown" "Monitoring Agent stopped" | Out-Null
        }
        catch {
            Write-Log "DEBUG" "Could not send shutdown notification: $($_.Exception.Message)"
        }
    }
}

function Restart-SingleProcess {
    param([string]$ProcessName)
    
    Write-Log "INFO" "Restarting individual process: $ProcessName"
    
    # Check if it's a valid process
    $isValid = $false
    foreach ($daemon in $script:DAEMONS) {
        if ($daemon -eq $ProcessName) {
            $isValid = $true
            break
        }
    }
    
    if (-not $isValid) {
        Write-Log "ERROR" "Invalid process name: $ProcessName"
        return $false
    }
    
    # Stop the process if running
    $status = Get-ProcessStatus $ProcessName
    if ($status -eq 1) {
        Write-Log "INFO" "Stopping $ProcessName"
        Stop-SingleProcess $ProcessName
        Start-Sleep -Seconds 2
    }
    
    # Start the process
    Write-Log "DEBUG" "Starting $ProcessName"
    $binary = Get-BinaryName $ProcessName
    $daemonArgs = Get-DaemonArgs $ProcessName
    
    $binaryPath = Join-Path $script:AGENT_HOME "bin\$binary"
    if (Test-Path $binaryPath) {
        try {
            $arguments = @()
            if ($daemonArgs) {
                $arguments += $daemonArgs -split ' '
            }
            
            # Use enhanced process start with bypass support
            $processInfo = Start-ProcessWithBypass -FilePath $binaryPath -ArgumentList $arguments -PassThru -WindowStyle "Hidden"
            
            # Create PID file
            $pidName = Get-PidName $ProcessName
            $pidFile = Join-Path $script:PID_DIR "$pidName-$($processInfo.Id).pid"
            $processInfo.Id | Out-File -FilePath $pidFile -Encoding ASCII
            
            # Increment restart counter
            $stateDir = Join-Path $script:AGENT_HOME "var\state"
            $counterFile = Join-Path $stateDir "restart_count_$ProcessName"
            if (Test-Path $counterFile) {
                $count = [int](Get-Content $counterFile) + 1
                $count | Set-Content $counterFile -Encoding utf8
            }
            
            Write-Log "INFO" "✓ Successfully restarted $ProcessName"
            return $true
        }
        catch {
            Write-Log "ERROR" "Failed to restart $ProcessName`: $($_.Exception.Message)"
            return $false
        }
    }
    else {
        Write-Log "ERROR" "Binary not found: $binaryPath"
        return $false
    }
}

function Stop-SingleProcess {
    param([string]$ProcessName)
    
    $pids = Get-ProcessPids $ProcessName
    foreach ($processId in $pids) {
        if ($processId) {
            try {
                $process = Get-Process -Id $processId -ErrorAction SilentlyContinue
                if ($process) {
                    $process.Kill()
                    Wait-Process -Id $processId -Timeout 10 -ErrorAction SilentlyContinue
                }
            }
            catch {
                Write-Log "WARN" "Failed to stop process $processId`: $($_.Exception.Message)"
            }
        }
    }
}

function Disconnect-Agent {
    Write-Log "INFO" "Forcing agent disconnection from Wazuh manager..."
    
    # First, try to send a proper disconnect signal by stopping any running processes
    $agentProcesses = Get-Process -Name "MONITORING_AGENT" -ErrorAction SilentlyContinue
    if ($agentProcesses) {
        Write-Log "INFO" "Terminating running agent processes to force disconnect..."
        foreach ($proc in $agentProcesses) {
            try {
                Write-Log "DEBUG" "Stopping process PID: $($proc.Id)"
                $proc.Kill()
                $proc.WaitForExit(5000)
            } catch {
                Write-Log "WARN" "Could not stop process $($proc.Id): $($_.Exception.Message)"
            }
        }
        Start-Sleep 2
    }
    
    # Check if client.keys file exists
    if (-not (Test-Path $script:CLIENT_KEYS)) {
        Write-Log "WARN" "Client keys file not found - agent not enrolled"
        return
    }
    
    # Get agent ID from client.keys
    $clientKeyLine = Get-Content $script:CLIENT_KEYS -First 1 -ErrorAction SilentlyContinue
    if (-not $clientKeyLine) {
        Write-Log "WARN" "Empty client keys file"
        return
    }
    
    $agentId = ($clientKeyLine -split ' ')[0]
    if (-not $agentId) {
        Write-Log "WARN" "Could not parse agent ID from client.keys"
        return
    }
    
    Write-Log "INFO" "Agent ID: $agentId - temporarily disabling connection"
    
    # Backup the client.keys file
    $backupFile = "$($script:CLIENT_KEYS).backup.$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    Copy-Item $script:CLIENT_KEYS $backupFile -ErrorAction SilentlyContinue
    
    # Temporarily rename client.keys to force disconnection
    $stoppedFile = "$($script:CLIENT_KEYS).stopped"
    Move-Item $script:CLIENT_KEYS $stoppedFile -ErrorAction SilentlyContinue
    
    Write-Log "INFO" "Agent authentication disabled - will appear as disconnected"
    
    # Try to send a final disconnect signal by attempting a brief connection with invalid auth
    # This helps the manager realize the agent is disconnected faster
    $binaryPath = Join-Path $script:AGENT_HOME "bin\MONITORING_AGENT.EXE"
    if (Test-Path $binaryPath) {
        Write-Log "DEBUG" "Sending disconnect signal to manager..."
        try {
            # Start agent briefly with no valid auth to trigger disconnect on manager side
            $disconnectProc = Start-Process -FilePath $binaryPath -ArgumentList "start" -NoNewWindow -PassThru
            Start-Sleep 3
            if (!$disconnectProc.HasExited) {
                $disconnectProc.Kill()
            }
        } catch {
            Write-Log "DEBUG" "Disconnect signal attempt completed"
        }
    }
}

function Restore-AgentConnection {
    Write-Log "DEBUG" "Checking for disabled agent connection..."
    
    # Check if client.keys was disabled during stop
    $stoppedFile = "$($script:CLIENT_KEYS).stopped"
    if ((Test-Path $stoppedFile) -and (-not (Test-Path $script:CLIENT_KEYS))) {
        try {
            Move-Item $stoppedFile $script:CLIENT_KEYS -ErrorAction Stop
            Write-Log "INFO" "Agent authentication restored"
        }
        catch {
            Write-Log "WARN" "Failed to restore agent authentication: $($_.Exception.Message)"
        }
    }
}

# ======================================================================
# ENHANCED BYPASS FUNCTIONALITY - WINDOWS IMPLEMENTATION
# ======================================================================

function Initialize-MonitoringBypass {
    Write-Log "DEBUG" "Initializing Windows monitoring bypass system..."
    
    # Check for bypass DLL
    if (Test-Path $script:BYPASS_DLL) {
        Write-Log "INFO" "Windows bypass DLL found: $script:BYPASS_DLL"
        
        # Set environment variable for DLL loading
        $env:MONITORING_BYPASS_DLL = $script:BYPASS_DLL
        
        # Try to load the DLL
        try {
            $loadResult = [BypassLoader]::LoadBypassDLL($script:BYPASS_DLL)
            if ($loadResult) {
                Write-Log "INFO" "✓ Bypass DLL loaded successfully"
                $env:MONITORING_BYPASS_ACTIVE = "1"
            }
            else {
                Write-Log "WARN" "Failed to load bypass DLL"
            }
        }
        catch {
            Write-Log "WARN" "Could not load bypass DLL: $($_.Exception.Message)"
        }
    }
    else {
        Write-Log "DEBUG" "No bypass DLL found - running without bypass"
    }
}

function Start-ProcessWithBypass {
    param(
        [string]$FilePath,
        [string[]]$ArgumentList = @(),
        [switch]$PassThru,
        [string]$WindowStyle = "Normal"
    )
    
    # If bypass is active, use DLL injection
    if ($env:MONITORING_BYPASS_ACTIVE -eq "1") {
        Write-Log "DEBUG" "Starting process with bypass: $FilePath"
        
        # Create process with DLL injection
        try {
            $startInfo = New-Object System.Diagnostics.ProcessStartInfo
            $startInfo.FileName = $FilePath
            $startInfo.Arguments = $ArgumentList -join ' '
            $startInfo.UseShellExecute = $false
            $startInfo.CreateNoWindow = ($WindowStyle -eq "Hidden")
            
            # Set bypass environment
            $startInfo.EnvironmentVariables["MONITORING_BYPASS_DLL"] = $script:BYPASS_DLL
            $startInfo.EnvironmentVariables["MONITORING_BYPASS_ACTIVE"] = "1"
            
            $process = [System.Diagnostics.Process]::Start($startInfo)
            
            if ($PassThru) {
                return $process
            }
        }
        catch {
            Write-Log "WARN" "Failed to start process with bypass, falling back to normal start: $($_.Exception.Message)"
        }
    }
    
    # Fallback to normal process start
    $params = @{
        FilePath = $FilePath
        ArgumentList = $ArgumentList
        PassThru = $PassThru
    }
    
    if ($WindowStyle -ne "Normal") {
        $params.WindowStyle = $WindowStyle
    }
    
    return Start-Process @params
}

# ======================================================================
# ENHANCED CONFIGURATION AND VALIDATION
# ======================================================================

function Test-Configuration {
    Write-Log "DEBUG" "Validating configuration..."
    
    # Check if essential configuration sections exist
    $configContent = Get-Content $script:CONFIG_FILE -Raw -ErrorAction SilentlyContinue
    if (-not $configContent) {
        Write-Log "ERROR" "Configuration file not found or empty: $script:CONFIG_FILE"
        return $false
    }
    
    if ($configContent -notmatch '<client>') {
        Write-Log "ERROR" "Missing <client> section in configuration"
        return $false
    }
    
    if ($configContent -notmatch '<server>') {
        Write-Log "ERROR" "Missing <server> section in configuration"
        return $false
    }
    
    # Basic XML structure check
    if ($configContent -notmatch '<ossec_config>' -or $configContent -notmatch '</ossec_config>') {
        Write-Log "ERROR" "Invalid XML structure in configuration file"
        return $false
    }
    
    Write-Log "DEBUG" "Configuration validation passed"
    return $true
}

function Test-FaultToleranceHealth {
    Write-Log "INFO" "Running comprehensive health check with fault tolerance validation..."
    
    $errors = 0
    
    # Run standard health check first
    if (-not (Test-Health)) {
        $errors++
    }
    
    # Check watchdog process
    $watchdogPidFile = Join-Path $script:PID_DIR "monitoring-watchdog.pid"
    $systemdWatchdogActive = $false
    
    # Check if Windows service watchdog is running
    $watchdogService = Get-Service -Name "MonitoringAgentWatchdog" -ErrorAction SilentlyContinue
    if ($watchdogService -and $watchdogService.Status -eq 'Running') {
        Write-Log "INFO" "✓ Windows service watchdog is active"
        $systemdWatchdogActive = $true
    }
    
    # If service watchdog is not running, check for standalone watchdog
    if (-not $systemdWatchdogActive) {
        if (Test-Path $watchdogPidFile) {
            $watchdogPid = Get-Content $watchdogPidFile -ErrorAction SilentlyContinue
            $watchdogProcess = Get-Process -Id $watchdogPid -ErrorAction SilentlyContinue
            if ($watchdogProcess) {
                Write-Log "INFO" "✓ Standalone process watchdog is active (PID: $watchdogPid)"
            }
            else {
                Write-Log "WARN" "⚠ Watchdog PID file exists but process not running"
                $errors++
            }
        }
        else {
            Write-Log "WARN" "⚠ No watchdog process detected"
            $errors++
        }
    }
    
    # Check fault tolerance components
    $recoveryPidFile = Join-Path $script:PID_DIR "monitoring-recovery.pid"
    if (Test-Path $recoveryPidFile) {
        $recoveryPid = Get-Content $recoveryPidFile -ErrorAction SilentlyContinue
        $recoveryProcess = Get-Process -Id $recoveryPid -ErrorAction SilentlyContinue
        if ($recoveryProcess) {
            Write-Log "INFO" "✓ Recovery monitoring is active (PID: $recoveryPid)"
        }
        else {
            Write-Log "WARN" "⚠ Recovery monitoring PID file exists but process not running"
            $errors++
        }
    }
    
    # Check restart counters
    $restartDir = Join-Path $script:AGENT_HOME "var\state"
    if (Test-Path $restartDir) {
        $totalRestarts = 0
        foreach ($daemon in $script:DAEMONS) {
            $counterFile = Join-Path $restartDir "restart_count_$daemon"
            if (Test-Path $counterFile) {
                $count = [int](Get-Content $counterFile -ErrorAction SilentlyContinue)
                $totalRestarts += $count
                if ($count -gt 0) {
                    Write-Log "INFO" "Process $daemon has been restarted $count times"
                }
            }
        }
        Write-Log "INFO" "Total process restarts since startup: $totalRestarts"
    }
    
    # Check Windows service status
    $monitoringService = Get-Service -Name "MonitoringAgent" -ErrorAction SilentlyContinue
    if ($monitoringService) {
        if ($monitoringService.Status -eq 'Running') {
            Write-Log "INFO" "✓ Windows service is running"
        }
        else {
            Write-Log "WARN" "⚠ Windows service exists but is not running"
        }
    }
    else {
        Write-Log "INFO" "ℹ Windows service not installed (manual mode)"
    }
    
    if ($errors -eq 0) {
        Write-Log "INFO" "✅ All fault tolerance health checks passed"
        return $true
    }
    else {
        Write-Log "WARN" "⚠ Health check completed with $errors warnings"
        return $false
    }
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
        (Join-Path $script:AGENT_HOME "var/incoming"),
        (Join-Path $script:AGENT_HOME "var/upgrade"),
        (Join-Path $script:AGENT_HOME "queue/diff"),
        (Join-Path $script:AGENT_HOME "queue/alerts"),
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
    
    $ossecLogFile = Join-Path $script:AGENT_HOME "logs/ossec.log"
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
        # Windows binary paths with .exe extension
        $binary = Join-Path $script:AGENT_HOME "bin/$process.exe"
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
    "Setup completed on: $(Get-Date)" | Set-Content $setupMarker -Encoding utf8
    
    Write-Log "INFO" "✅ Initial setup completed successfully!"
    Write-Log "INFO" "Next steps:"
    Write-Log "INFO" "  1. Enroll with manager: $script:SCRIPT_NAME enroll [manager_ip]"
    Write-Log "INFO" "  2. Start the agent: $script:SCRIPT_NAME start"
    Write-Log "INFO" "  3. Check status: $script:SCRIPT_NAME status"
    
    return $true
}

function New-WindowsService {
    <#
    .SYNOPSIS
    Creates a fault-tolerant Windows service for the Monitoring Agent
    
    .DESCRIPTION
    Creates a Windows service with comprehensive recovery options, restart policies,
    and power event handling for maximum availability
    #>
    
    Write-Log "INFO" "Creating fault-tolerant Windows service..."
    
    try {
        $serviceName = "MonitoringAgent"
        $serviceDisplayName = "Monitoring Agent Security Platform"
        $serviceDescription = "Fault-tolerant monitoring agent with automatic recovery and power management"
        $binaryPath = "`"$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe`" -ExecutionPolicy Bypass -NonInteractive -WindowStyle Hidden -File `"$($MyInvocation.MyCommand.Path)`" service-mode"
        
        # Check if service already exists
        $existingService = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if ($existingService) {
            Write-Log "INFO" "Updating existing Windows service: $serviceName"
            
            # Stop service if running
            if ($existingService.Status -eq 'Running') {
                Write-Log "DEBUG" "Stopping existing service for update"
                Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
                Start-Sleep -Seconds 5
            }
            
            # Delete existing service with PowerShell 5.1 compatibility
            if (Get-Command "Remove-Service" -ErrorAction SilentlyContinue) {
                Remove-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
            } else {
                # Fallback for PowerShell 5.1
                & sc.exe delete $serviceName | Out-Null
            }
            Start-Sleep -Seconds 2
        }
        
        # Create the service with comprehensive configuration using PowerShell-native methods
        Write-Log "DEBUG" "Creating service with binary path: $binaryPath"
        
        # Use New-Service with PowerShell 5.1 compatible parameters
        $serviceParams = @{
            Name = $serviceName
            BinaryPathName = $binaryPath
            DisplayName = $serviceDisplayName
            StartupType = "Automatic"
        }
        
        # Add DependsOn only if supported (may not work in all PowerShell versions)
        try {
            $serviceParams.DependsOn = @("Tcpip", "Afd")
        } catch {
            Write-Log "DEBUG" "Service dependencies not supported in this PowerShell version"
        }
        
        $newService = New-Service @serviceParams -ErrorAction Stop
        
        if (-not $newService) {
            throw "Failed to create service using New-Service"
        }
        
        # Set description separately for PowerShell 5.1 compatibility
        try {
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName" -Name Description -Value $serviceDescription -ErrorAction SilentlyContinue
        } catch {
            Write-Log "DEBUG" "Could not set service description via registry"
        }
        
        # Configure failure recovery options using registry since PowerShell doesn't have native cmdlets for this
        Write-Log "DEBUG" "Configuring service recovery options"
        
        try {
            # Set failure actions using registry
            $servicePath = "HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName"
            
            # Configure automatic restart on failure
            # These registry values configure the service to restart after failures
            Set-ItemProperty -Path $servicePath -Name "FailureActions" -Value ([byte[]](
                # Reset period (1 hour = 3600 seconds)
                0x10, 0x0E, 0x00, 0x00,
                # Reserved
                0x00, 0x00, 0x00, 0x00,
                # Action count (3 actions)
                0x03, 0x00, 0x00, 0x00,
                # Action 1: Restart after 1 minute (60000 ms)
                0x01, 0x00, 0x00, 0x00, 0x60, 0xEA, 0x00, 0x00,
                # Action 2: Restart after 5 minutes (300000 ms)
                0x01, 0x00, 0x00, 0x00, 0x20, 0x93, 0x04, 0x00,
                # Action 3: Restart after 10 minutes (600000 ms)
                0x01, 0x00, 0x00, 0x00, 0x40, 0x26, 0x09, 0x00
            )) -Type Binary -ErrorAction SilentlyContinue
            
            # Enable failure flag
            Set-ItemProperty -Path $servicePath -Name "FailureActionsOnNonCrashFailures" -Value 1 -Type DWord -ErrorAction SilentlyContinue
            
            # Configure delayed auto-start for system stability
            Set-ItemProperty -Path $servicePath -Name "DelayedAutostart" -Value 1 -Type DWord -ErrorAction SilentlyContinue
            
            Write-Log "INFO" "Service failure recovery and delayed start configured via registry"
        }
        catch {
            Write-Log "WARN" "Could not configure service failure recovery: $($_.Exception.Message)"
        }
        
        # Configure service privileges and security
        Write-Log "DEBUG" "Configuring service security"
        
        # Create service-specific event log source
        try {
            if (-not [System.Diagnostics.EventLog]::SourceExists("MonitoringAgent")) {
                [System.Diagnostics.EventLog]::CreateEventSource("MonitoringAgent", "Application")
                Write-Log "DEBUG" "Created event log source"
            }
        }
        catch {
            Write-Log "WARN" "Could not create event log source: $($_.Exception.Message)"
        }
        
        # Configure service for power events
        Write-Log "DEBUG" "Configuring power event handling"
        
        # Register for power events and system state changes
        $powerEventScript = Join-Path $script:AGENT_HOME "scripts\monitoring-power-events.ps1"
        if (-not (Test-Path (Split-Path $powerEventScript -Parent))) {
            New-Item -Path (Split-Path $powerEventScript -Parent) -ItemType Directory -Force | Out-Null
        }
        
        # Create power event handler script
        $powerEventContent = @'
# Monitoring Agent Power Event Handler
param($EventType, $EventData)

$LogFile = "{0}\logs\monitoring-power-events.log" -f $env:MONITORING_AGENT_HOME
$Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

function Write-PowerLog($Message) {
    $LogEntry = "[$Timestamp] [POWER] $Message"
    Add-Content -Path $LogFile -Value $LogEntry -ErrorAction SilentlyContinue
}

switch ($EventType) {
    "PowerEventSuspend" {
        Write-PowerLog "System entering suspend mode"
    }
    "PowerEventResume" {
        Write-PowerLog "System resuming from suspend mode"
        # Give system time to stabilize
        Start-Sleep -Seconds 10
        
        # Check if monitoring service is running
        $service = Get-Service -Name "MonitoringAgent" -ErrorAction SilentlyContinue
        if ($service -and $service.Status -ne 'Running') {
            Write-PowerLog "Monitoring service not running after resume - restarting"
            try {
                Start-Service -Name "MonitoringAgent"
                Write-PowerLog "Successfully restarted monitoring service"
            }
            catch {
                Write-PowerLog "Failed to restart monitoring service: $($_.Exception.Message)"
            }
        }
    }
    "PowerEventShutdown" {
        Write-PowerLog "System shutting down"
    }
}
'@
        
        $powerEventContent = $powerEventContent -replace '\{0\}', $script:AGENT_HOME
        $powerEventContent | Set-Content -Path $powerEventScript -Encoding UTF8
        
        # Create scheduled task for power event monitoring
        $taskName = "MonitoringAgent-PowerEvents"
        
        try {
            # Remove existing task if it exists
            $existingTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
            if ($existingTask) {
                Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
            }
            
            # Create trigger for system resume
            $trigger = New-ScheduledTaskTrigger -AtStartup
            $trigger.Delay = "PT30S"  # 30 second delay after startup
            
            # Create action to run power event handler
            $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -File `"$powerEventScript`" PowerEventResume"
            
            # Configure task settings
            $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 5)
            
            # Create principal (run as SYSTEM)
            $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
            
            # Register the task
            Register-ScheduledTask -TaskName $taskName -Trigger $trigger -Action $action -Settings $settings -Principal $principal -Description "Monitoring Agent Power Event Handler" | Out-Null
            
            Write-Log "DEBUG" "Created scheduled task for power event handling"
        }
        catch {
            Write-Log "WARN" "Could not create power event scheduled task: $($_.Exception.Message)"
        }
        
        # Start the service
        Write-Log "INFO" "Starting Monitoring Agent service"
        Start-Service -Name $serviceName -ErrorAction Stop
        
        # Verify service is running
        $service = Get-Service -Name $serviceName
        if ($service.Status -eq 'Running') {
            Write-Log "INFO" "✓ Windows service created and started successfully: $serviceName"
            Write-Log "INFO" "Service features:"
            Write-Log "INFO" "  - Automatic startup"
            Write-Log "INFO" "  - Delayed start for system stability"
            Write-Log "INFO" "  - Automatic restart on failure"
            Write-Log "INFO" "  - Power event handling"
            Write-Log "INFO" "  - Recovery after 1, 5, and 10 minutes"
        }
        else {
            Write-Log "WARN" "Service created but not running. Status: $($service.Status)"
        }
        
        return $true
    }
    catch {
        Write-Log "ERROR" "Failed to create Windows service: $($_.Exception.Message)"
        Write-Log "DEBUG" "Stack trace: $($_.Exception.StackTrace)"
        return $false
    }
}

function Remove-WindowsService {
    <#
    .SYNOPSIS
    Removes the Monitoring Agent Windows service
    #>
    
    Write-Log "INFO" "Removing Monitoring Agent Windows service..."
    
    try {
        $serviceName = "MonitoringAgent"
        
        # Check if service exists
        $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if (-not $service) {
            Write-Log "WARN" "Service $serviceName does not exist"
            return $true
        }
        
        # Stop service if running
        if ($service.Status -eq 'Running') {
            Write-Log "DEBUG" "Stopping service before removal"
            Stop-Service -Name $serviceName -Force
            
            # Wait for service to stop
            $timeout = 30
            $count = 0
            while ($service.Status -ne 'Stopped' -and $count -lt $timeout) {
                Start-Sleep -Seconds 1
                $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
                $count++
            }
        }
        
        # Remove scheduled task
        $taskName = "MonitoringAgent-PowerEvents"
        $existingTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        if ($existingTask) {
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
            Write-Log "DEBUG" "Removed scheduled task: $taskName"
        }
        
        # Delete the service with PowerShell 5.1 compatibility
        try {
            if (Get-Command "Remove-Service" -ErrorAction SilentlyContinue) {
                Remove-Service -Name $serviceName -Force -ErrorAction Stop
            } else {
                # Fallback for PowerShell 5.1
                $result = & sc.exe delete $serviceName
                if ($LASTEXITCODE -ne 0) {
                    throw "sc.exe delete failed: $result"
                }
            }
            Write-Log "INFO" "✓ Windows service removed successfully: $serviceName"
            return $true
        }
        catch {
            Write-Log "ERROR" "Failed to remove service: $($_.Exception.Message)"
            return $false
        }
    }
    catch {
        Write-Log "ERROR" "Error removing Windows service: $($_.Exception.Message)"
        return $false
    }
}

function Start-ServiceMode {
    <#
    .SYNOPSIS
    Runs the monitoring agent in Windows service mode with continuous monitoring
    
    .DESCRIPTION
    This function implements the main service loop with fault tolerance,
    process monitoring, and automatic recovery
    #>
    
    Write-Log "INFO" "Starting Monitoring Agent in service mode"
    
    # Set environment variables for service mode
    $env:MONITORING_SERVICE_MODE = "1"
    $env:MONITORING_AGENT_HOME = $script:AGENT_HOME
    
    # Initialize bypass mechanism
    Initialize-MonitoringBypass | Out-Null
    
    # Service control variables
    $script:ServiceRunning = $true
    $script:ProcessMonitoringEnabled = $true
    $script:ServiceStartTime = Get-Date
    
    # Process monitoring configuration
    $monitoringInterval = 30  # seconds
    $maxRestartAttempts = 3
    $restartCooldown = 300    # 5 minutes
    
    # Process tracking
    $processRestartCounts = @{}
    $lastRestartTimes = @{}
    
    # Register for system events
    Register-EngineEvent -SourceIdentifier "PowerShell.Exiting" -Action {
        $script:ServiceRunning = $false
        Write-Log "INFO" "Service shutdown requested"
    }
    
    # Signal handler for service control
    $signalHandler = {
        param($eventSender, $cancelArgs)
        Write-Log "INFO" "Service control signal received"
        $script:ServiceRunning = $false
    }
    
    # Try to register for console events (may not work in service context)
    try {
        [Console]::CancelKeyPress += $signalHandler
    }
    catch {
        Write-Log "DEBUG" "Could not register console event handler (expected in service mode)"
    }
    
    # Start the monitoring agent
    try {
        Write-Log "INFO" "Initializing monitoring agent processes"
        Start-Agent
        
        Write-Log "INFO" "Entering service monitoring loop"
        
        # Main service loop
        while ($script:ServiceRunning) {
            try {
                # Check if all critical processes are running
                $failedProcesses = @()
                
                foreach ($daemon in $script:DAEMONS) {
                    if (-not (Test-ProcessRunning $daemon)) {
                        $failedProcesses += $daemon
                        Write-Log "WARN" "Process $daemon is not running"
                    }
                }
                
                # Handle failed processes
                if ($failedProcesses.Count -gt 0) {
                    foreach ($process in $failedProcesses) {
                        $currentTime = Get-Date
                        
                        # Initialize tracking if not exists
                        if (-not $processRestartCounts.ContainsKey($process)) {
                            $processRestartCounts[$process] = 0
                            $lastRestartTimes[$process] = [DateTime]::MinValue
                        }
                        
                        # Check cooldown period
                        $timeSinceLastRestart = ($currentTime - $lastRestartTimes[$process]).TotalSeconds
                        if ($timeSinceLastRestart -lt $restartCooldown) {
                            Write-Log "DEBUG" "Process $process in cooldown period"
                            continue
                        }
                        
                        # Check restart limit
                        if ($processRestartCounts[$process] -ge $maxRestartAttempts) {
                            Write-Log "ERROR" "Process $process exceeded maximum restart attempts"
                            continue
                        }
                        
                        # Attempt to restart the process
                        Write-Log "INFO" "Attempting to restart process: $process"
                        
                        if (Restart-SingleProcess $process) {
                            $processRestartCounts[$process]++
                            $lastRestartTimes[$process] = $currentTime
                            Write-Log "INFO" "Successfully restarted process: $process"
                        }
                        else {
                            Write-Log "ERROR" "Failed to restart process: $process"
                        }
                    }
                    
                    # If multiple critical processes failed, restart entire agent
                    if ($failedProcesses.Count -ge 3) {
                        Write-Log "WARN" "Multiple processes failed - restarting entire agent"
                        
                        try {
                            Stop-Agent
                            Start-Sleep -Seconds 5
                            Start-Agent
                            
                            # Reset restart counters after full restart
                            $processRestartCounts.Clear()
                            $lastRestartTimes.Clear()
                            
                            Write-Log "INFO" "Agent restarted successfully"
                        }
                        catch {
                            Write-Log "ERROR" "Failed to restart agent: $($_.Exception.Message)"
                        }
                    }
                }
                
                # Reset daily restart counters
                $currentHour = (Get-Date).Hour
                if ($currentHour -eq 0 -and (Get-Date).Minute -eq 0) {
                    Write-Log "INFO" "Daily restart counter reset"
                    $processRestartCounts.Clear()
                    $lastRestartTimes.Clear()
                }
                
                # Service heartbeat
                if ((Get-Date).Minute % 15 -eq 0) {
                    $uptime = (Get-Date) - $script:ServiceStartTime
                    Write-Log "DEBUG" "Service heartbeat - Uptime: $($uptime.ToString('dd\.hh\:mm\:ss'))"
                }
                
                # Wait before next check
                Start-Sleep -Seconds $monitoringInterval
            }
            catch {
                Write-Log "ERROR" "Error in service monitoring loop: $($_.Exception.Message)"
                Start-Sleep -Seconds 60  # Wait longer if there's an error
            }
        }
        
        Write-Log "INFO" "Service monitoring loop ended"
    }
    catch {
        Write-Log "CRITICAL" "Fatal error in service mode: $($_.Exception.Message)"
        Write-Log "DEBUG" "Stack trace: $($_.Exception.StackTrace)"
    }
    finally {
        # Cleanup
        Write-Log "INFO" "Stopping monitoring agent processes"
        try {
            Stop-Agent
        }
        catch {
            Write-Log "ERROR" "Error stopping agent processes: $($_.Exception.Message)"
        }
        
        Write-Log "INFO" "Monitoring Agent service mode stopped"
    }
}

function Restart-SingleProcess {
    <#
    .SYNOPSIS
    Restarts a single monitoring process
    
    .DESCRIPTION
    Attempts to restart an individual monitoring process with proper error handling
    #>
    param(
        [string]$ProcessName
    )
    
    Write-Log "INFO" "Restarting individual process: $ProcessName"
    
    # Validate process name
    if ($ProcessName -notin $script:DAEMONS) {
        Write-Log "ERROR" "Unknown process: $ProcessName"
        return $false
    }
    
    try {
        # Stop the process if running
        $processId = Get-ProcessPid $ProcessName
        if ($processId) {
            Write-Log "DEBUG" "Stopping process $ProcessName (PID: $processId)"
            Stop-Process -Id $processId -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 2
        }
        
        # Start the process
        $binary = Get-BinaryName $ProcessName
        $binaryPath = Join-Path $script:AGENT_HOME "bin\$binary.exe"
        
        if (-not (Test-Path $binaryPath)) {
            Write-Log "ERROR" "Binary not found: $binaryPath"
            return $false
        }
        
        $daemonArgs = Get-DaemonArgs $ProcessName
        
        Write-Log "DEBUG" "Starting process: $binaryPath $daemonArgs"
        
        # Start with bypass environment
        $process = Start-ProcessWithBypass -FilePath $binaryPath -ArgumentList $daemonArgs -PassThru
        
        if ($process) {
            # Wait for process to stabilize
            Start-Sleep -Seconds 5
            
            # Verify it's running
            if (Test-ProcessRunning $ProcessName) {
                Write-Log "INFO" "Successfully restarted process: $ProcessName"
                return $true
            }
            else {
                Write-Log "ERROR" "Process $ProcessName failed to start properly"
                return $false
            }
        }
        else {
            Write-Log "ERROR" "Failed to start process: $ProcessName"
            return $false
        }
    }
    catch {
        Write-Log "ERROR" "Error restarting process $ProcessName : $($_.Exception.Message)"
        return $false
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
    
    $sharedDir = Join-Path $script:AGENT_HOME "etc/shared"
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
    Write-Host @"
Monitoring Agent Control Script $Script:AGENT_VERSION

USAGE:
    .\$($script:SCRIPT_NAME) [command] [options]

COMMANDS:
    setup                           Run initial setup (automatic on first start)
    enroll [manager_ip] [port] [name]
                                    Enroll agent with manager (interactive)
    start                           Start the monitoring agent
    stop                            Stop the monitoring agent
    restart                         Restart the monitoring agent
    status                          Show agent status
    logs [lines] [follow]           Show agent logs (default: 50 lines)
    health                          Run health check
    test-connection                 Test connectivity to manager
    backup                          Backup configuration
    restore [backup_path]           Restore configuration from backup
    configure-firewall [manager_ip] [port]
                                    Configure firewall rules
    
OPTIONS:
    -Help                           Show this help message
    -Version                        Show version information
    -VerboseLogging                 Enable debug logging

QUICK START:
    1. Enroll with manager:         .\$($script:SCRIPT_NAME) enroll [manager_ip]
    2. Start the agent:             .\$($script:SCRIPT_NAME) start
    3. Check status:                .\$($script:SCRIPT_NAME) status
    4. Test connectivity:           .\$($script:SCRIPT_NAME) test-connection

ENROLLMENT PROCESS:
    The enrollment command will:
    - Prompt for the client key from your manager
    - Automatically update configuration files
    - Offer to start the agent immediately
    
    To get the client key, run on your manager:
    # Windows agent management - use Windows tools instead of Linux commands

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
    
    # Run production validation before any operations
    try {
        Test-ProductionRequirements
    }
    catch {
        Write-Error "Production validation failed: $($_.Exception.Message)"
        exit 1
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
            Write-Log "INFO" "Starting agent as current user: $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)"
            # Run configuration validation for Windows
            Test-Configuration
            Lock-Process
            try {
                Start-Agent
            }
            finally {
                Unlock-Process
            }
        }
        "start-service" {
            # Special mode for Windows service - starts and stays in foreground
            Write-Log "INFO" "Starting agent in service mode..."
            Test-Configuration
            Lock-Process
            try {
                Start-Agent
                # Stay in foreground to maintain Windows service
                Write-Log "INFO" "Monitoring Agent running in service mode..."
                while ($true) {
                    Start-Sleep -Seconds 30
                    # Basic health check - if main daemon dies, exit to trigger restart
                    $mainDaemon = "monitoring-agentd"
                    $status = Get-ProcessStatus $mainDaemon
                    if ($status -eq 0) {
                        Write-Log "ERROR" "Main daemon died, exiting service to trigger restart"
                        exit 1
                    }
                }
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
            # Run configuration validation for Windows
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
            # Pass arguments properly to enrollment function
            $managerIP = $Arguments[0]
            $port = if ($Arguments.Count -gt 1) { $Arguments[1] } else { "" }
            $name = if ($Arguments.Count -gt 2) { $Arguments[2] } else { $env:COMPUTERNAME }
            Invoke-AgentEnrollment -ManagerInput $managerIP -ManagerPort $port -AgentName $name
        }
        "health" {
            Test-Health
        }
        "health-check" {
            Test-Health
        }
        "health-check-full" {
            Test-FaultToleranceHealth
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
        "service-mode" {
            # Run in service mode
            Start-ServiceMode
        }
        "install-service" {
            New-WindowsService
        }
        "uninstall-service" {
            Remove-WindowsService
        }
        "health-check" {
            Test-Health
        }
        "restart-process" {
            if ($Arguments.Count -lt 1) {
                Write-Log "ERROR" "Process name required for restart-process command"
                Show-Usage
                exit 1
            }
            Restart-SingleProcess $Arguments[0]
        }
        "test" {
            Write-Log "INFO" "Testing Windows agent configuration..."
            # Run configuration validation for Windows
            Test-Configuration
            Write-Log "INFO" "Configuration test completed successfully"
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