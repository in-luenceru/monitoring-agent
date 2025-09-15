# Monitoring Agent Control Script for Windows
# Professional agent management tool for Windows systems
# Copyright (C) 2025, Monitoring Solutions Inc.
# Version: 1.0.0

#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [Parameter(Position=0, Mandatory=$true)]
    [ValidateSet('start', 'stop', 'restart', 'status', 'logs', 'enroll', 'health', 'backup', 'restore', 'configure-firewall', 'help', 'version')]
    [string]$Command,
    
    [Parameter(Position=1)]
    [string]$Parameter1,
    
    [Parameter(Position=2)]
    [string]$Parameter2,
    
    [Parameter(Position=3)]
    [string]$Parameter3,
    
    [Parameter(Position=4)]
    [string]$Parameter4,
    
    [Parameter(Position=5)]
    [string]$Parameter5,
    
    [switch]$Debug
)

# Set strict mode and error action
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Configuration variables
$script:ScriptVersion = "1.0.0"
$script:AgentHome = Split-Path -Parent $PSScriptRoot
$script:ServiceName = "MonitoringAgent"
$script:DisplayName = "Monitoring Agent Service"
$script:ConfigFile = Join-Path $AgentHome "etc\ossec.conf"
$script:ClientKeys = Join-Path $AgentHome "etc\client.keys"
$script:LogFile = Join-Path $AgentHome "logs\monitoring-agent.log"
$script:BackupDir = Join-Path $AgentHome "backup"

# Process names (Windows service names)
$script:Services = @(
    "MonitoringModules",
    "MonitoringLogCollector", 
    "MonitoringSyscheck",
    "MonitoringAgent",
    "MonitoringExec"
)

# Logging function
function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateSet('ERROR', 'WARN', 'INFO', 'DEBUG')]
        [string]$Level,
        
        [Parameter(Mandatory=$true)]
        [string]$Message
    )
    
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logEntry = "[$timestamp] [$Level] $Message"
    
    # Ensure log directory exists
    $logDir = Split-Path -Parent $LogFile
    if (-not (Test-Path $logDir)) {
        New-Item -ItemType Directory -Path $logDir -Force | Out-Null
    }
    
    # Write to log file
    Add-Content -Path $LogFile -Value $logEntry -Encoding UTF8
    
    # Write to console with colors
    switch ($Level) {
        'ERROR' {
            Write-Host "[ERROR] $Message" -ForegroundColor Red
        }
        'WARN' {
            Write-Host "[WARN] $Message" -ForegroundColor Yellow
        }
        'INFO' {
            Write-Host "[INFO] $Message" -ForegroundColor Green
        }
        'DEBUG' {
            if ($Debug) {
                Write-Host "[DEBUG] $Message" -ForegroundColor Blue
            }
        }
    }
}

# Input validation functions
function Test-IPAddress {
    [CmdletBinding()]
    param([string]$IPAddress)
    
    try {
        $ip = [System.Net.IPAddress]::Parse($IPAddress)
        return $true
    }
    catch {
        # Check if it's a valid hostname
        if ($IPAddress -match '^[a-zA-Z0-9.-]+$') {
            return $true
        }
        return $false
    }
}

function Test-Port {
    [CmdletBinding()]
    param([string]$Port)
    
    $portNum = 0
    if ([int]::TryParse($Port, [ref]$portNum)) {
        return ($portNum -ge 1 -and $portNum -le 65535)
    }
    return $false
}

function Test-AgentId {
    [CmdletBinding()]
    param([string]$AgentId)
    
    return ($AgentId -match '^\d{3,10}$')
}

# Security functions
function Test-FilePermissions {
    [CmdletBinding()]
    param(
        [string]$FilePath,
        [string]$ExpectedOwner = "SYSTEM"
    )
    
    if (-not (Test-Path $FilePath)) {
        Write-Log -Level ERROR -Message "File does not exist: $FilePath"
        return $false
    }
    
    try {
        $acl = Get-Acl -Path $FilePath
        $owner = $acl.Owner
        
        # Check if SYSTEM or Administrators have full control
        $hasProperPermissions = $false
        foreach ($access in $acl.Access) {
            if ($access.IdentityReference -match "(SYSTEM|Administrators)" -and 
                $access.FileSystemRights -eq "FullControl") {
                $hasProperPermissions = $true
                break
            }
        }
        
        if (-not $hasProperPermissions) {
            Write-Log -Level WARN -Message "Insufficient permissions for $FilePath"
            return $false
        }
        
        return $true
    }
    catch {
        Write-Log -Level ERROR -Message "Failed to check permissions for $FilePath`: $($_.Exception.Message)"
        return $false
    }
}

function Set-SecurePermissions {
    [CmdletBinding()]
    param()
    
    Write-Log -Level INFO -Message "Setting secure file permissions..."
    
    $directories = @(
        $AgentHome,
        (Join-Path $AgentHome "bin"),
        (Join-Path $AgentHome "etc"),
        (Join-Path $AgentHome "logs"),
        (Join-Path $AgentHome "var")
    )
    
    foreach ($dir in $directories) {
        if (Test-Path $dir) {
            try {
                $acl = Get-Acl -Path $dir
                $acl.SetAccessRuleProtection($true, $false)
                
                # Add SYSTEM full control
                $systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                    "SYSTEM", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow"
                )
                $acl.SetAccessRule($systemRule)
                
                # Add Administrators full control
                $adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                    "Administrators", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow"
                )
                $acl.SetAccessRule($adminRule)
                
                Set-Acl -Path $dir -AclObject $acl
            }
            catch {
                Write-Log -Level WARN -Message "Failed to set permissions for $dir`: $($_.Exception.Message)"
            }
        }
    }
    
    # Set specific file permissions
    $files = @($ConfigFile, $ClientKeys)
    foreach ($file in $files) {
        if (Test-Path $file) {
            try {
                $acl = Get-Acl -Path $file
                $acl.SetAccessRuleProtection($true, $false)
                
                # Add SYSTEM full control
                $systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                    "SYSTEM", "FullControl", "None", "None", "Allow"
                )
                $acl.SetAccessRule($systemRule)
                
                # Add Administrators read/write
                $adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                    "Administrators", "ReadAndExecute", "None", "None", "Allow"
                )
                $acl.SetAccessRule($adminRule)
                
                Set-Acl -Path $file -AclObject $acl
            }
            catch {
                Write-Log -Level WARN -Message "Failed to set permissions for $file`: $($_.Exception.Message)"
            }
        }
    }
}

# Service management functions
function Test-ServiceRunning {
    [CmdletBinding()]
    param([string]$ServiceName)
    
    try {
        $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        return ($service -and $service.Status -eq 'Running')
    }
    catch {
        return $false
    }
}

function Wait-ForService {
    [CmdletBinding()]
    param(
        [string]$ServiceName,
        [ValidateSet('Running', 'Stopped')]
        [string]$DesiredState,
        [int]$TimeoutSeconds = 30
    )
    
    $timeout = (Get-Date).AddSeconds($TimeoutSeconds)
    
    do {
        try {
            $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
            if ($service -and $service.Status -eq $DesiredState) {
                return $true
            }
        }
        catch {
            # Service might not exist yet
        }
        
        Start-Sleep -Seconds 1
    } while ((Get-Date) -lt $timeout)
    
    return $false
}

# Agent management functions
function Start-Agent {
    [CmdletBinding()]
    param()
    
    Write-Log -Level INFO -Message "Starting Monitoring Agent..."
    
    # Check if already running
    if (Test-AgentRunning) {
        Write-Log -Level WARN -Message "Monitoring Agent is already running"
        return $true
    }
    
    # Validate configuration
    if (-not (Test-Configuration)) {
        Write-Log -Level ERROR -Message "Configuration validation failed"
        return $false
    }
    
    # Set permissions
    Set-SecurePermissions
    
    # Start services
    $startedServices = @()
    foreach ($service in $Services) {
        try {
            Write-Log -Level DEBUG -Message "Starting service: $service"
            
            $svc = Get-Service -Name $service -ErrorAction SilentlyContinue
            if ($svc) {
                Start-Service -Name $service -ErrorAction Stop
                
                if (Wait-ForService -ServiceName $service -DesiredState 'Running') {
                    $startedServices += $service
                    Write-Log -Level INFO -Message "$service started successfully"
                }
                else {
                    Write-Log -Level ERROR -Message "Failed to start $service"
                    # Stop already started services
                    foreach ($started in $startedServices) {
                        Stop-Service -Name $started -Force -ErrorAction SilentlyContinue
                    }
                    return $false
                }
            }
            else {
                Write-Log -Level WARN -Message "Service not found: $service"
            }
        }
        catch {
            Write-Log -Level ERROR -Message "Failed to start $service`: $($_.Exception.Message)"
            # Stop already started services
            foreach ($started in $startedServices) {
                Stop-Service -Name $started -Force -ErrorAction SilentlyContinue
            }
            return $false
        }
    }
    
    Write-Log -Level INFO -Message "Monitoring Agent started successfully"
    return $true
}

function Stop-Agent {
    [CmdletBinding()]
    param()
    
    Write-Log -Level INFO -Message "Stopping Monitoring Agent..."
    
    if (-not (Test-AgentRunning)) {
        Write-Log -Level WARN -Message "Monitoring Agent is not running"
        return $true
    }
    
    # Stop services in reverse order
    $reversedServices = $Services | Sort-Object { $Services.IndexOf($_) } -Descending
    
    foreach ($service in $reversedServices) {
        try {
            $svc = Get-Service -Name $service -ErrorAction SilentlyContinue
            if ($svc -and $svc.Status -eq 'Running') {
                Write-Log -Level DEBUG -Message "Stopping service: $service"
                Stop-Service -Name $service -Force -ErrorAction Stop
                
                if (Wait-ForService -ServiceName $service -DesiredState 'Stopped') {
                    Write-Log -Level INFO -Message "$service stopped successfully"
                }
                else {
                    Write-Log -Level WARN -Message "Failed to stop $service gracefully"
                }
            }
        }
        catch {
            Write-Log -Level WARN -Message "Error stopping $service`: $($_.Exception.Message)"
        }
    }
    
    Write-Log -Level INFO -Message "Monitoring Agent stopped successfully"
    return $true
}

function Restart-Agent {
    [CmdletBinding()]
    param()
    
    Write-Log -Level INFO -Message "Restarting Monitoring Agent..."
    Stop-Agent
    Start-Sleep -Seconds 3
    Start-Agent
}

function Test-AgentRunning {
    [CmdletBinding()]
    param()
    
    # Check if main agent service is running
    return (Test-ServiceRunning -ServiceName "MonitoringAgent")
}

function Get-AgentStatus {
    [CmdletBinding()]
    param()
    
    Write-Host "Monitoring Agent Status Report" -ForegroundColor White
    Write-Host "==============================" -ForegroundColor White
    Write-Host "Configuration file: $ConfigFile"
    Write-Host "Log file: $LogFile"
    Write-Host "Service status:"
    
    $allRunning = $true
    foreach ($service in $Services) {
        try {
            $svc = Get-Service -Name $service -ErrorAction SilentlyContinue
            if ($svc) {
                $status = $svc.Status
                $color = if ($status -eq 'Running') { 'Green' } else { 'Red'; $allRunning = $false }
                Write-Host "  $service`: " -NoNewline
                Write-Host $status -ForegroundColor $color
            }
            else {
                Write-Host "  $service`: " -NoNewline
                Write-Host "NOT INSTALLED" -ForegroundColor Red
                $allRunning = $false
            }
        }
        catch {
            Write-Host "  $service`: " -NoNewline
            Write-Host "ERROR" -ForegroundColor Red
            $allRunning = $false
        }
    }
    
    Write-Host ""
    Write-Host "Overall status: " -NoNewline
    if ($allRunning) {
        Write-Host "RUNNING" -ForegroundColor Green
    }
    else {
        Write-Host "STOPPED" -ForegroundColor Red
    }
    
    # Show connection status
    if (Test-ServiceRunning -ServiceName "MonitoringAgent") {
        Write-Host ""
        Write-Host "Connection status:"
        if (Test-Path $LogFile) {
            $recentLogs = Get-Content -Path $LogFile -Tail 100 -ErrorAction SilentlyContinue
            if ($recentLogs -join "`n" -match "Connected to enrollment service") {
                Write-Host "  Manager connection: " -NoNewline
                Write-Host "CONNECTED" -ForegroundColor Green
            }
            else {
                Write-Host "  Manager connection: " -NoNewline
                Write-Host "UNKNOWN" -ForegroundColor Yellow
            }
        }
    }
    
    # Show resource usage
    Write-Host ""
    Write-Host "Resource usage:"
    foreach ($service in $Services) {
        try {
            $svc = Get-Service -Name $service -ErrorAction SilentlyContinue
            if ($svc -and $svc.Status -eq 'Running') {
                $process = Get-Process -Id (Get-WmiObject -Class Win32_Service -Filter "Name='$service'").ProcessId -ErrorAction SilentlyContinue
                if ($process) {
                    $cpu = [math]::Round($process.CPU, 2)
                    $memory = [math]::Round($process.WorkingSet / 1MB, 2)
                    Write-Host "  $service`: CPU: ${cpu}s, Memory: ${memory}MB"
                }
            }
        }
        catch {
            # Skip if unable to get process info
        }
    }
}

function Test-Configuration {
    [CmdletBinding()]
    param()
    
    Write-Log -Level DEBUG -Message "Validating configuration..."
    
    if (-not (Test-Path $ConfigFile)) {
        Write-Log -Level ERROR -Message "Configuration file not found: $ConfigFile"
        return $false
    }
    
    # Check XML syntax
    try {
        [xml]$xml = Get-Content -Path $ConfigFile -Raw
        Write-Log -Level DEBUG -Message "XML syntax validation passed"
    }
    catch {
        Write-Log -Level ERROR -Message "Invalid XML syntax in configuration file: $($_.Exception.Message)"
        return $false
    }
    
    # Check for required sections
    $requiredSections = @('client', 'syscheck', 'rootcheck')
    foreach ($section in $requiredSections) {
        if (-not $xml.SelectSingleNode("//$section")) {
            Write-Log -Level ERROR -Message "Missing required section: $section"
            return $false
        }
    }
    
    Write-Log -Level DEBUG -Message "Configuration validation passed"
    return $true
}

function Show-Logs {
    [CmdletBinding()]
    param(
        [int]$Lines = 50,
        [switch]$Follow
    )
    
    if (-not (Test-Path $LogFile)) {
        Write-Log -Level WARN -Message "Log file not found: $LogFile"
        return
    }
    
    if ($Follow) {
        Write-Log -Level INFO -Message "Following log file (Ctrl+C to stop)..."
        Get-Content -Path $LogFile -Tail $Lines -Wait
    }
    else {
        Write-Log -Level INFO -Message "Showing last $Lines lines of log file:"
        Get-Content -Path $LogFile -Tail $Lines
    }
}

function Register-Agent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$ManagerIP,
        
        [string]$ManagerPort = "1514",
        
        [string]$AgentName = $env:COMPUTERNAME,
        
        [string]$AgentId,
        
        [string]$AgentKey
    )
    
    Write-Log -Level INFO -Message "Enrolling agent with manager..."
    
    # Input validation
    if (-not (Test-IPAddress -IPAddress $ManagerIP)) {
        Write-Log -Level ERROR -Message "Invalid manager IP address: $ManagerIP"
        return $false
    }
    
    if (-not (Test-Port -Port $ManagerPort)) {
        Write-Log -Level ERROR -Message "Invalid manager port: $ManagerPort"
        return $false
    }
    
    if ($AgentId -and -not (Test-AgentId -AgentId $AgentId)) {
        Write-Log -Level ERROR -Message "Invalid agent ID: $AgentId"
        return $false
    }
    
    # Sanitize agent name
    $AgentName = $AgentName -replace '[^\w.-]', '' | ForEach-Object { $_.Substring(0, [Math]::Min($_.Length, 32)) }
    
    if ([string]::IsNullOrEmpty($AgentName)) {
        Write-Log -Level ERROR -Message "Invalid agent name"
        return $false
    }
    
    # Update configuration
    Write-Log -Level DEBUG -Message "Updating configuration with manager details..."
    
    # Backup current configuration
    $backupPath = "$ConfigFile.backup.$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    Copy-Item -Path $ConfigFile -Destination $backupPath -Force
    
    # Update manager address and port
    try {
        [xml]$config = Get-Content -Path $ConfigFile -Raw
        
        $serverNode = $config.SelectSingleNode("//server/address")
        if ($serverNode) {
            $serverNode.InnerText = $ManagerIP
        }
        
        $portNode = $config.SelectSingleNode("//server/port")
        if ($portNode) {
            $portNode.InnerText = $ManagerPort
        }
        
        $config.Save($ConfigFile)
    }
    catch {
        Write-Log -Level ERROR -Message "Failed to update configuration: $($_.Exception.Message)"
        return $false
    }
    
    # Set up client keys if provided
    if ($AgentId -and $AgentKey) {
        Write-Log -Level DEBUG -Message "Setting up client authentication..."
        $keyEntry = "$AgentId $AgentName $ManagerIP $AgentKey"
        Set-Content -Path $ClientKeys -Value $keyEntry -Encoding UTF8
        Set-SecurePermissions
    }
    
    Write-Log -Level INFO -Message "Agent enrolled successfully"
    Write-Log -Level INFO -Message "Manager: ${ManagerIP}:${ManagerPort}"
    Write-Log -Level INFO -Message "Agent name: $AgentName"
    
    return $true
}

function New-AgentKey {
    [CmdletBinding()]
    param()
    
    # Generate a random 64-character hex key
    $bytes = New-Object byte[] 32
    [System.Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($bytes)
    return [System.BitConverter]::ToString($bytes) -replace '-'
}

function Set-FirewallRule {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$ManagerIP,
        
        [string]$ManagerPort = "1514"
    )
    
    Write-Log -Level INFO -Message "Configuring Windows Firewall rules..."
    
    try {
        # Remove existing rule if it exists
        Remove-NetFirewallRule -DisplayName "Monitoring Agent Outbound" -ErrorAction SilentlyContinue
        
        # Add new outbound rule
        New-NetFirewallRule -DisplayName "Monitoring Agent Outbound" `
                           -Direction Outbound `
                           -Protocol TCP `
                           -RemoteAddress $ManagerIP `
                           -RemotePort $ManagerPort `
                           -Action Allow `
                           -Profile Any `
                           -Description "Allow Monitoring Agent to connect to manager"
        
        Write-Log -Level INFO -Message "Firewall rule configured successfully"
    }
    catch {
        Write-Log -Level ERROR -Message "Failed to configure firewall rule: $($_.Exception.Message)"
        return $false
    }
    
    return $true
}

function Backup-Configuration {
    [CmdletBinding()]
    param()
    
    $backupPath = Join-Path $BackupDir (Get-Date -Format 'yyyyMMdd_HHmmss')
    
    Write-Log -Level INFO -Message "Creating configuration backup..."
    
    try {
        # Create backup directory
        New-Item -ItemType Directory -Path $backupPath -Force | Out-Null
        
        # Backup configuration files
        if (Test-Path $ConfigFile) {
            Copy-Item -Path $ConfigFile -Destination $backupPath -Force
        }
        
        if (Test-Path $ClientKeys) {
            Copy-Item -Path $ClientKeys -Destination $backupPath -Force
        }
        
        # Backup shared directory
        $sharedDir = Join-Path (Split-Path $ConfigFile) "shared"
        if (Test-Path $sharedDir) {
            Copy-Item -Path $sharedDir -Destination $backupPath -Recurse -Force
        }
        
        # Backup logs
        $logsDir = Split-Path $LogFile
        if (Test-Path $logsDir) {
            Get-ChildItem -Path $logsDir -Filter "*.log" | ForEach-Object {
                Copy-Item -Path $_.FullName -Destination $backupPath -Force
            }
        }
        
        Write-Log -Level INFO -Message "Backup created at: $backupPath"
        return $true
    }
    catch {
        Write-Log -Level ERROR -Message "Failed to create backup: $($_.Exception.Message)"
        return $false
    }
}

function Restore-Configuration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$BackupPath
    )
    
    if (-not (Test-Path $BackupPath)) {
        Write-Log -Level ERROR -Message "Backup directory not found: $BackupPath"
        return $false
    }
    
    Write-Log -Level INFO -Message "Restoring configuration from backup..."
    
    try {
        # Stop agent before restore
        Stop-Agent | Out-Null
        
        # Restore files
        $backupConfig = Join-Path $BackupPath "ossec.conf"
        if (Test-Path $backupConfig) {
            Copy-Item -Path $backupConfig -Destination $ConfigFile -Force
        }
        
        $backupKeys = Join-Path $BackupPath "client.keys"
        if (Test-Path $backupKeys) {
            Copy-Item -Path $backupKeys -Destination $ClientKeys -Force
        }
        
        Set-SecurePermissions
        
        Write-Log -Level INFO -Message "Configuration restored successfully"
        return $true
    }
    catch {
        Write-Log -Level ERROR -Message "Failed to restore configuration: $($_.Exception.Message)"
        return $false
    }
}

function Test-Health {
    [CmdletBinding()]
    param()
    
    Write-Log -Level INFO -Message "Running health check..."
    
    $errors = 0
    
    # Check configuration
    if (-not (Test-Configuration)) {
        Write-Log -Level ERROR -Message "Configuration validation failed"
        $errors++
    }
    
    # Check file permissions
    $criticalFiles = @($ConfigFile, $ClientKeys)
    foreach ($file in $criticalFiles) {
        if ((Test-Path $file) -and -not (Test-FilePermissions -FilePath $file)) {
            Write-Log -Level ERROR -Message "Incorrect permissions for $file"
            $errors++
        }
    }
    
    # Check disk space
    $drive = Split-Path -Qualifier $AgentHome
    $driveInfo = Get-WmiObject -Class Win32_LogicalDisk -Filter "DeviceID='$drive'"
    $freeSpaceMB = [math]::Round($driveInfo.FreeSpace / 1MB, 2)
    
    if ($freeSpaceMB -lt 100) {
        Write-Log -Level WARN -Message "Low disk space: ${freeSpaceMB}MB available"
        $errors++
    }
    
    # Check log file size
    if (Test-Path $LogFile) {
        $logSize = (Get-Item $LogFile).Length
        if ($logSize -gt 104857600) {  # 100MB
            Write-Log -Level WARN -Message "Log file is large: $logSize bytes"
        }
    }
    
    # Check Windows Event Log for errors
    try {
        $recentErrors = Get-WinEvent -FilterHashtable @{LogName='Application'; Level=2; StartTime=(Get-Date).AddHours(-1)} -MaxEvents 10 -ErrorAction SilentlyContinue |
                       Where-Object { $_.ProviderName -like "*Monitoring*" }
        
        if ($recentErrors) {
            Write-Log -Level WARN -Message "Found $($recentErrors.Count) recent errors in Windows Event Log"
        }
    }
    catch {
        # Event log check failed, continue
    }
    
    if ($errors -eq 0) {
        Write-Log -Level INFO -Message "Health check passed"
        return $true
    }
    else {
        Write-Log -Level ERROR -Message "Health check failed with $errors errors"
        return $false
    }
}

function Show-Usage {
    [CmdletBinding()]
    param()
    
    Write-Host @"
Monitoring Agent Control Script v$ScriptVersion

USAGE:
    .\monitoring-agent-control.ps1 <command> [options]

COMMANDS:
    start                           Start the monitoring agent
    stop                            Stop the monitoring agent
    restart                         Restart the monitoring agent
    status                          Show agent status
    logs [lines] [follow]           Show agent logs (default: 50 lines)
    enroll <manager_ip> [port] [name] [id] [key]
                                    Enroll agent with manager
    health                          Run health check
    backup                          Backup configuration
    restore <backup_path>           Restore configuration from backup
    configure-firewall <manager_ip> [port]
                                    Configure firewall rules
    help                            Show this help message
    version                         Show version information

OPTIONS:
    -Debug                          Enable debug logging

EXAMPLES:
    .\monitoring-agent-control.ps1 start
    .\monitoring-agent-control.ps1 status
    .\monitoring-agent-control.ps1 logs 100
    .\monitoring-agent-control.ps1 enroll 192.168.1.100 1514 my-agent
    .\monitoring-agent-control.ps1 configure-firewall 192.168.1.100 1514

SECURITY NOTES:
    - Must run as Administrator for full functionality
    - Configuration files are protected with NTFS permissions
    - All inputs are validated and sanitized
    - Logs contain no sensitive information

For support and documentation, visit: https://docs.monitoring-solutions.com
"@ -ForegroundColor White
}

function Show-Version {
    [CmdletBinding()]
    param()
    
    Write-Host "Monitoring Agent Control Script"
    Write-Host "Version: $ScriptVersion"
    Write-Host "Copyright (C) 2025, Monitoring Solutions Inc."
    Write-Host "License: Commercial License"
    Write-Host "PowerShell Version: $($PSVersionTable.PSVersion)"
    Write-Host "OS Version: $([System.Environment]::OSVersion.VersionString)"
}

# Main execution logic
try {
    switch ($Command.ToLower()) {
        'start' {
            if (-not (Start-Agent)) {
                exit 1
            }
        }
        'stop' {
            if (-not (Stop-Agent)) {
                exit 1
            }
        }
        'restart' {
            Restart-Agent
        }
        'status' {
            Get-AgentStatus
        }
        'logs' {
            $lines = if ($Parameter1) { [int]$Parameter1 } else { 50 }
            $follow = if ($Parameter2 -eq 'true') { $true } else { $false }
            Show-Logs -Lines $lines -Follow:$follow
        }
        'enroll' {
            if (-not $Parameter1) {
                Write-Log -Level ERROR -Message "Manager IP address required for enrollment"
                Show-Usage
                exit 1
            }
            
            $result = Register-Agent -ManagerIP $Parameter1 -ManagerPort $Parameter2 -AgentName $Parameter3 -AgentId $Parameter4 -AgentKey $Parameter5
            if (-not $result) {
                exit 1
            }
        }
        'health' {
            if (-not (Test-Health)) {
                exit 1
            }
        }
        'backup' {
            if (-not (Backup-Configuration)) {
                exit 1
            }
        }
        'restore' {
            if (-not $Parameter1) {
                Write-Log -Level ERROR -Message "Backup path required for restore"
                Show-Usage
                exit 1
            }
            
            if (-not (Restore-Configuration -BackupPath $Parameter1)) {
                exit 1
            }
        }
        'configure-firewall' {
            if (-not $Parameter1) {
                Write-Log -Level ERROR -Message "Manager IP address required for firewall configuration"
                Show-Usage
                exit 1
            }
            
            if (-not (Set-FirewallRule -ManagerIP $Parameter1 -ManagerPort $Parameter2)) {
                exit 1
            }
        }
        'help' {
            Show-Usage
        }
        'version' {
            Show-Version
        }
        default {
            Write-Log -Level ERROR -Message "Unknown command: $Command"
            Show-Usage
            exit 1
        }
    }
}
catch {
    Write-Log -Level ERROR -Message "Script execution failed: $($_.Exception.Message)"
    if ($Debug) {
        Write-Host $_.ScriptStackTrace -ForegroundColor Red
    }
    exit 1
}

exit 0