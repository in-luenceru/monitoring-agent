#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Enhanced Monitoring Agent Auto-Startup Script with Watchdog Functionality
    
.DESCRIPTION
    This script provides robust auto-startup functionality for the Monitoring Agent and Suricata IDS.
    Features:
    - Intelligent startup with retries and backoff
    - Continuous watchdog monitoring
    - Service health checks and automatic recovery
    - Comprehensive logging and error handling
    - System event monitoring for startup triggers
    
.PARAMETER Mode
    Operation mode: 'startup' for initial startup, 'watchdog' for continuous monitoring
    
.PARAMETER Duration
    Watchdog monitoring duration in minutes (0 for infinite)
    
.AUTHOR
    Custom Security Solutions
    
.VERSION
    2.0.0
#>

param(
    [ValidateSet("startup", "watchdog", "test")]
    [string]$Mode = "startup",
    
    [int]$Duration = 0,
    
    [switch]$NoWait
)

# Script Configuration
$Script:AgentPath = Split-Path -Parent $MyInvocation.MyCommand.Path
$Script:AgentExe = Join-Path $AgentPath "monitoring-agent.exe"
$Script:SuricataPath = Join-Path $AgentPath "suricata"
$Script:SuricataControl = Join-Path $SuricataPath "SuricataControl.ps1"
$Script:LogFile = Join-Path $AgentPath "logs\auto-startup.log"
$Script:WatchdogPidFile = Join-Path $AgentPath "state\watchdog.pid"
$Script:ControlScript = Join-Path $AgentPath "MonitoringAgentControl.ps1"
$Script:RiskNoXControl = Join-Path $AgentPath "RiskNoX-Agent-Installer.ps1"

# Watchdog Configuration
$Script:WatchdogConfig = @{
    CheckInterval = 30          # Check every 30 seconds
    StartupRetries = 5          # Maximum startup retry attempts
    RetryDelay = 60             # Delay between retries (seconds)
    HealthCheckTimeout = 10     # Health check timeout (seconds)
    RestartCooldown = 120       # Minimum time between restarts (seconds)
    MaxRestartAttempts = 3      # Maximum restart attempts per hour
}

# Startup delays for different scenarios
$Script:StartupDelays = @{
    SystemBoot = 45             # Delay after system boot
    UserLogon = 15              # Delay after user logon
    ServiceRecovery = 30        # Delay for service recovery
    WakeFromSleep = 20          # Delay after wake from sleep
}

# Global state tracking
$Script:LastRestartTime = @{}
$Script:RestartCounts = @{}
$Script:WatchdogRunning = $false

#region Logging Functions
function Write-AutoStartupLog {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        
        [Parameter(Mandatory=$false)]
        [ValidateSet("INFO", "WARN", "ERROR", "SUCCESS", "DEBUG")]
        [string]$Level = "INFO"
    )
    
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $ProcessId = [System.Diagnostics.Process]::GetCurrentProcess().Id
    $LogEntry = "[$Timestamp] [PID:$ProcessId] [$Level] [$Mode] $Message"
    
    # Ensure logs directory exists
    $LogDir = Split-Path $Script:LogFile -Parent
    if (!(Test-Path $LogDir)) {
        New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
    }
    
    # Write to log file
    try {
        Add-Content -Path $Script:LogFile -Value $LogEntry -ErrorAction SilentlyContinue
    }
    catch {
        # Continue silently if unable to write to log
    }
    
    # Also output to console if running interactively
    if ([Environment]::UserInteractive) {
        switch ($Level) {
            "INFO"    { Write-Host $LogEntry -ForegroundColor Cyan }
            "WARN"    { Write-Host $LogEntry -ForegroundColor Yellow }
            "ERROR"   { Write-Host $LogEntry -ForegroundColor Red }
            "SUCCESS" { Write-Host $LogEntry -ForegroundColor Green }
            "DEBUG"   { Write-Host $LogEntry -ForegroundColor Gray }
        }
    }
}

function Write-EventLog {
    param(
        [string]$Message,
        [string]$EventType = "Information"
    )
    
    try {
        # Create event source if it doesn't exist
        if (!(Get-EventLog -LogName Application -Source "MonitoringAgent" -ErrorAction SilentlyContinue)) {
            New-EventLog -LogName Application -Source "MonitoringAgent" -ErrorAction SilentlyContinue
        }
        
        Write-EventLog -LogName Application -Source "MonitoringAgent" -EventId 1000 -EntryType $EventType -Message $Message -ErrorAction SilentlyContinue
    }
    catch {
        # Continue silently if unable to write to event log
    }
}
#endregion

#region Utility Functions
function Test-AdminRights {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-SystemUptime {
    try {
        $bootTime = (Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime
        return (Get-Date) - $bootTime
    }
    catch {
        return [TimeSpan]::Zero
    }
}

function Test-NetworkConnectivity {
    try {
        # Test basic network connectivity
        $result = Test-NetConnection -ComputerName "8.8.8.8" -Port 53 -InformationLevel Quiet -WarningAction SilentlyContinue -ErrorAction SilentlyContinue
        return $result
    }
    catch {
        return $false
    }
}

function Wait-ForSystemReady {
    param([int]$MaxWaitSeconds = 300)
    
    Write-AutoStartupLog "Waiting for system to be ready..." "INFO"
    $startTime = Get-Date
    
    while (((Get-Date) - $startTime).TotalSeconds -lt $MaxWaitSeconds) {
        # Check if network is available
        if (Test-NetworkConnectivity) {
            Write-AutoStartupLog "System is ready (network connectivity confirmed)" "SUCCESS"
            return $true
        }
        
        Write-AutoStartupLog "Waiting for network connectivity..." "DEBUG"
        Start-Sleep -Seconds 5
    }
    
    Write-AutoStartupLog "System readiness timeout after $MaxWaitSeconds seconds" "WARN"
    return $false
}

function Get-ProcessWorkingDirectory {
    param([int]$ProcessId)
    
    try {
        $process = Get-CimInstance -ClassName Win32_Process -Filter "ProcessId = $ProcessId" -ErrorAction SilentlyContinue
        if ($process) {
            # Try to get the executable path and derive working directory
            $executablePath = $process.ExecutablePath
            if ($executablePath) {
                return Split-Path $executablePath -Parent
            }
        }
    }
    catch {
        # Continue silently
    }
    
    return $null
}

function Test-ProcessFromWorkspace {
    param([int]$ProcessId, [string]$ProcessName)
    
    try {
        $workingDir = Get-ProcessWorkingDirectory -ProcessId $ProcessId
        if ($workingDir) {
            $normalizedWorkspace = [System.IO.Path]::GetFullPath($Script:AgentPath).TrimEnd('\')
            $normalizedWorkingDir = [System.IO.Path]::GetFullPath($workingDir).TrimEnd('\')
            
            return $normalizedWorkingDir -eq $normalizedWorkspace
        }
    }
    catch {
        # Continue silently
    }
    
    return $false
}
#endregion

#region Service Status Functions
function Get-MonitoringAgentStatus {
    try {
        # Get all monitoring-agent processes
        $processes = Get-Process -Name "monitoring-agent" -ErrorAction SilentlyContinue
        
        if ($processes) {
            foreach ($process in $processes) {
                # Check if this process is from our workspace
                if (Test-ProcessFromWorkspace -ProcessId $process.Id -ProcessName "monitoring-agent") {
                    return @{
                        Running = $true
                        ProcessId = $process.Id
                        StartTime = $process.StartTime
                        WorkingSet = $process.WorkingSet64
                        FromWorkspace = $true
                    }
                }
            }
        }
        
        return @{
            Running = $false
            ProcessId = $null
            StartTime = $null
            WorkingSet = 0
            FromWorkspace = $false
        }
    }
    catch {
        Write-AutoStartupLog "Error checking agent status: $($_.Exception.Message)" "ERROR"
        return @{
            Running = $false
            ProcessId = $null
            StartTime = $null
            WorkingSet = 0
            FromWorkspace = $false
        }
    }
}

function Get-SuricataStatus {
    try {
        if (!(Test-Path $Script:SuricataControl)) {
            return @{
                Available = $false
                Running = $false
                ProcessId = $null
                StartTime = $null
                FromWorkspace = $false
            }
        }
        
        # Check for Suricata PID file which is more reliable
        $suricataPidFile = Join-Path $Script:AgentPath "state\suricata.pid"
        
        if (Test-Path $suricataPidFile) {
            $suricataPid = Get-Content $suricataPidFile -ErrorAction SilentlyContinue
            if ($suricataPid -and $suricataPid -match '^\d+$') {
                $process = Get-Process -Id $suricataPid -ErrorAction SilentlyContinue
                if ($process -and $process.ProcessName -eq "suricata") {
                    return @{
                        Available = $true
                        Running = $true
                        ProcessId = $process.Id
                        StartTime = $process.StartTime
                        WorkingSet = $process.WorkingSet64
                        FromWorkspace = $true
                    }
                }
            }
        }
        
        # Fallback: check for any Suricata processes (less reliable but better than nothing)
        $processes = Get-Process -Name "suricata" -ErrorAction SilentlyContinue
        if ($processes) {
            $process = $processes[0]  # Take the first one
            return @{
                Available = $true
                Running = $true
                ProcessId = $process.Id
                StartTime = $process.StartTime
                WorkingSet = $process.WorkingSet64
                FromWorkspace = $true  # Assume it's ours if it exists
            }
        }
        
        return @{
            Available = $true
            Running = $false
            ProcessId = $null
            StartTime = $null
            WorkingSet = 0
            FromWorkspace = $false
        }
    }
    catch {
        Write-AutoStartupLog "Error checking Suricata status: $($_.Exception.Message)" "ERROR"
        return @{
            Available = $true
            Running = $false
            ProcessId = $null
            StartTime = $null
            WorkingSet = 0
            FromWorkspace = $false
        }
    }
}

function Get-RiskNoXAgentStatus {
    try {
        if (!(Test-Path $Script:RiskNoXControl)) {
            return @{
                Available = $false
                Running = $false
                ProcessId = $null
                StartTime = $null
                FromWorkspace = $false
            }
        }
        
        # Check for RiskNoX backend processes (Python processes running backend_server.py)
        $processes = Get-Process python -ErrorAction SilentlyContinue | 
            Where-Object { 
                try {
                    $cmdLine = (Get-CimInstance -ClassName Win32_Process -Filter "ProcessId = $($_.Id)" -ErrorAction SilentlyContinue).CommandLine
                    return ($cmdLine -like "*backend_server.py*" -and $cmdLine -like "*$($Script:AgentPath)*")
                } catch {
                    return $false
                }
            }
        
        if ($processes) {
            # Take the first matching process
            $process = $processes[0]
            return @{
                Available = $true
                Running = $true
                ProcessId = $process.Id
                StartTime = $process.StartTime
                WorkingSet = $process.WorkingSet64
                FromWorkspace = $true
            }
        }
        
        return @{
            Available = $true
            Running = $false
            ProcessId = $null
            StartTime = $null
            WorkingSet = 0
            FromWorkspace = $false
        }
    }
    catch {
        Write-AutoStartupLog "Error checking RiskNoX Agent status: $($_.Exception.Message)" "ERROR"
        return @{
            Available = $true
            Running = $false
            ProcessId = $null
            StartTime = $null
            WorkingSet = 0
            FromWorkspace = $false
        }
    }
}

function Test-ServiceHealth {
    param([string]$ServiceName)
    
    $isHealthy = $false
    
    try {
        switch ($ServiceName) {
            "MonitoringAgent" {
                $status = Get-MonitoringAgentStatus
                if ($status.Running -and $status.FromWorkspace) {
                    # Test if process is responsive (basic health check)
                    $process = Get-Process -Id $status.ProcessId -ErrorAction SilentlyContinue
                    if ($process -and !$process.HasExited) {
                        # Check if process has been running for at least 30 seconds (startup completion)
                        $runningTime = (Get-Date) - $process.StartTime
                        if ($runningTime.TotalSeconds -ge 30) {
                            $isHealthy = $true
                        }
                    }
                }
            }
            
            "Suricata" {
                $status = Get-SuricataStatus
                if ($status.Available -and $status.Running -and $status.FromWorkspace) {
                    $process = Get-Process -Id $status.ProcessId -ErrorAction SilentlyContinue
                    if ($process -and !$process.HasExited) {
                        $runningTime = (Get-Date) - $process.StartTime
                        if ($runningTime.TotalSeconds -ge 30) {
                            $isHealthy = $true
                        }
                    }
                }
            }
            
            "RiskNoXAgent" {
                $status = Get-RiskNoXAgentStatus
                if ($status.Available -and $status.Running -and $status.FromWorkspace) {
                    $process = Get-Process -Id $status.ProcessId -ErrorAction SilentlyContinue
                    if ($process -and !$process.HasExited) {
                        $runningTime = (Get-Date) - $process.StartTime
                        if ($runningTime.TotalSeconds -ge 30) {
                            $isHealthy = $true
                        }
                    }
                }
            }
        }
    }
    catch {
        Write-AutoStartupLog "Health check failed for $ServiceName`: $($_.Exception.Message)" "ERROR"
        $isHealthy = $false
    }
    
    return $isHealthy
}
#endregion

#region Service Management Functions
function Start-MonitoringAgentWithRetry {
    param([int]$MaxRetries = 3)
    
    Write-AutoStartupLog "Starting Monitoring Agent with retry logic..." "INFO"
    
    for ($attempt = 1; $attempt -le $MaxRetries; $attempt++) {
        Write-AutoStartupLog "Startup attempt $attempt/$MaxRetries" "INFO"
        
        try {
            # Check if already running
            $status = Get-MonitoringAgentStatus
            if ($status.Running -and $status.FromWorkspace) {
                Write-AutoStartupLog "Monitoring Agent already running (PID: $($status.ProcessId))" "SUCCESS"
                return $true
            }
            
            # Use the control script to start the agent
            $startArgs = @(
                "-NoProfile"
                "-ExecutionPolicy", "Bypass"
                "-File", $Script:ControlScript
                "start"
            )
            
            Write-AutoStartupLog "Executing: pwsh.exe $($startArgs -join ' ')" "DEBUG"
            
            # Add timeout to prevent hanging - reduced timeout to allow more time for RiskNoX
            $processStartTime = Get-Date
            $process = Start-Process -FilePath "pwsh.exe" -ArgumentList $startArgs -WorkingDirectory $Script:AgentPath -WindowStyle Hidden -PassThru
            
            # Wait for process to complete with timeout (reduced from 120 to 90 seconds)
            $timeoutSeconds = 90  # 1.5 minutes timeout
            $processCompleted = $process.WaitForExit($timeoutSeconds * 1000)
            
            if (!$processCompleted) {
                Write-AutoStartupLog "Monitoring Agent start process timed out after $timeoutSeconds seconds, terminating..." "WARN"
                try {
                    $process.Kill()
                    $process.ExitCode = -1
                } catch {
                    Write-AutoStartupLog "Error terminating process: $($_.Exception.Message)" "WARN"
                }
            }
            
            Write-AutoStartupLog "Monitoring Agent start process completed with exit code: $($process.ExitCode)" "DEBUG"
            
            if ($process.ExitCode -eq 0) {
                Write-AutoStartupLog "Monitoring Agent start command succeeded, waiting for agent to fully initialize..." "INFO"
                
                # Wait for agent to fully start with retry logic
                $maxWaitAttempts = 6  # Wait up to 30 seconds (6 * 5 seconds)
                $waitAttempt = 0
                $agentStarted = $false
                
                while ($waitAttempt -lt $maxWaitAttempts -and !$agentStarted) {
                    $waitAttempt++
                    Start-Sleep -Seconds 5
                    
                    Write-AutoStartupLog "Verification attempt $waitAttempt/$maxWaitAttempts - checking agent status..." "DEBUG"
                    $newStatus = Get-MonitoringAgentStatus
                    Write-AutoStartupLog "Agent status: Running=$($newStatus.Running), FromWorkspace=$($newStatus.FromWorkspace), ProcessId=$($newStatus.ProcessId)" "DEBUG"
                    
                    if ($newStatus.Running -and $newStatus.FromWorkspace) {
                        $agentStarted = $true
                        Write-AutoStartupLog "Monitoring Agent started successfully (PID: $($newStatus.ProcessId))" "SUCCESS"
                        Write-EventLog "Monitoring Agent started successfully" "Information"
                        Write-AutoStartupLog "Returning true from monitoring agent startup" "DEBUG"
                        return $true
                    } else {
                        Write-AutoStartupLog "Agent not fully ready yet, waiting..." "DEBUG"
                    }
                }
                
                if (!$agentStarted) {
                    Write-AutoStartupLog "Agent start command completed but agent is not running after $($maxWaitAttempts * 5) seconds" "WARN"
                    Write-AutoStartupLog "Final status: Running=$($newStatus.Running), FromWorkspace=$($newStatus.FromWorkspace)" "DEBUG"
                }
            } else {
                Write-AutoStartupLog "Agent start command failed with exit code: $($process.ExitCode)" "ERROR"
            }
        }
        catch {
            Write-AutoStartupLog "Error during startup attempt $attempt`: $($_.Exception.Message)" "ERROR"
            # Continue to next attempt instead of failing completely
        }
        
        if ($attempt -lt $MaxRetries) {
            $delay = [math]::Min($Script:WatchdogConfig.RetryDelay, 30)  # Cap delay at 30 seconds
            Write-AutoStartupLog "Waiting $delay seconds before retry..." "INFO"
            Start-Sleep -Seconds $delay
        }
    }
    
    # Even if we failed to start the Monitoring Agent, don't prevent other services from starting
    Write-AutoStartupLog "Failed to start Monitoring Agent after $MaxRetries attempts, continuing with other services..." "WARN"
    Write-EventLog "Failed to start Monitoring Agent after $MaxRetries attempts" "Warning"
    return $false
}

function Start-SuricataWithRetry {
    param([int]$MaxRetries = 3)
    
    $suricataStatus = Get-SuricataStatus
    if (!$suricataStatus.Available) {
        Write-AutoStartupLog "Suricata is not available in this installation" "INFO"
        return $true  # Not an error if Suricata is not installed
    }
    
    Write-AutoStartupLog "Starting Suricata Network IDS with retry logic..." "INFO"
    
    for ($attempt = 1; $attempt -le $MaxRetries; $attempt++) {
        Write-AutoStartupLog "Suricata startup attempt $attempt/$MaxRetries" "INFO"
        
        try {
            # Check if already running
            $status = Get-SuricataStatus
            if ($status.Running -and $status.FromWorkspace) {
                Write-AutoStartupLog "Suricata already running (PID: $($status.ProcessId))" "SUCCESS"
                return $true
            }
            
            # Use the control script to start Suricata
            $startArgs = @(
                "-NoProfile"
                "-ExecutionPolicy", "Bypass"
                "-File", $Script:ControlScript
                "start-suricata"
            )
            
            Write-AutoStartupLog "Executing Suricata start: pwsh.exe $($startArgs -join ' ')" "DEBUG"
            
            $process = Start-Process -FilePath "pwsh.exe" -ArgumentList $startArgs -WorkingDirectory $Script:AgentPath -WindowStyle Hidden -PassThru -Wait
            
            if ($process.ExitCode -eq 0) {
                # Wait for Suricata to fully start
                Start-Sleep -Seconds 5
                
                # Verify Suricata started
                $newStatus = Get-SuricataStatus
                if ($newStatus.Running -and $newStatus.FromWorkspace) {
                    Write-AutoStartupLog "Suricata started successfully (PID: $($newStatus.ProcessId))" "SUCCESS"
                    Write-EventLog "Suricata Network IDS started successfully" "Information"
                    return $true
                } else {
                    Write-AutoStartupLog "Suricata start command completed but Suricata is not running" "WARN"
                }
            } else {
                Write-AutoStartupLog "Suricata start command failed with exit code: $($process.ExitCode)" "ERROR"
            }
        }
        catch {
            Write-AutoStartupLog "Error during Suricata startup attempt $attempt`: $($_.Exception.Message)" "ERROR"
        }
        
        if ($attempt -lt $MaxRetries) {
            $delay = $Script:WatchdogConfig.RetryDelay
            Write-AutoStartupLog "Waiting $delay seconds before Suricata retry..." "INFO"
            Start-Sleep -Seconds $delay
        }
    }
    
    Write-AutoStartupLog "Failed to start Suricata after $MaxRetries attempts" "ERROR"
    Write-EventLog "Failed to start Suricata Network IDS after $MaxRetries attempts" "Warning"
    return $false
}

function Start-RiskNoXAgentWithRetry {
    param([int]$MaxRetries = 3)
    
    $riskNoXStatus = Get-RiskNoXAgentStatus
    if (!$riskNoXStatus.Available) {
        Write-AutoStartupLog "RiskNoX Agent is not available in this installation" "INFO"
        return $true  # Not an error if RiskNoX is not installed
    }
    
    Write-AutoStartupLog "Starting RiskNoX Security Agent with retry logic..." "INFO"
    
    for ($attempt = 1; $attempt -le $MaxRetries; $attempt++) {
        Write-AutoStartupLog "RiskNoX Agent startup attempt $attempt/$MaxRetries" "INFO"
        
        try {
            # Check if already running
            $status = Get-RiskNoXAgentStatus
            if ($status.Running -and $status.FromWorkspace) {
                Write-AutoStartupLog "RiskNoX Agent already running (PID: $($status.ProcessId))" "SUCCESS"
                return $true
            }
            
            # Use the RiskNoX installer script to start the agent in background mode
            $installerScript = Join-Path $Script:AgentPath "RiskNoX-Agent-Installer.ps1"
            if (Test-Path $installerScript) {
                $startArgs = @(
                    "-NoProfile"
                    "-ExecutionPolicy", "Bypass"
                    "-File", $installerScript
                    "-Action", "start"
                )
                
                Write-AutoStartupLog "Executing RiskNoX start: pwsh.exe $($startArgs -join ' ')" "DEBUG"
                
                $process = Start-Process -FilePath "pwsh.exe" -ArgumentList $startArgs -WorkingDirectory $Script:AgentPath -WindowStyle Hidden -PassThru
                
                # Wait for the installer process to complete with timeout
                $timeout = 30  # 30 seconds timeout
                $completed = $process.WaitForExit($timeout * 1000)
                
                if (!$completed) {
                    Write-AutoStartupLog "RiskNoX installer timeout after $timeout seconds, checking if services started..." "WARN"
                } else {
                    Write-AutoStartupLog "RiskNoX installer completed with exit code: $($process.ExitCode)" "DEBUG"
                }
                
                # Wait for RiskNoX agent to fully start (regardless of installer exit code)
                Start-Sleep -Seconds 5
                
                # Verify RiskNoX agent started
                $newStatus = Get-RiskNoXAgentStatus
                if ($newStatus.Running -and $newStatus.FromWorkspace) {
                    Write-AutoStartupLog "RiskNoX Agent started successfully (PID: $($newStatus.ProcessId))" "SUCCESS"
                    Write-EventLog "RiskNoX Security Agent started successfully" "Information"
                    return $true
                } else {
                    Write-AutoStartupLog "RiskNoX Agent start command completed but agent is not running" "WARN"
                }
            } else {
                # Fallback to RiskNoX control script without ShowLogs
                Write-AutoStartupLog "Installer script not found, using control script..." "INFO"
                
                # Create a modified command that doesn't hang
                $controlScript = @"
                    Import-Module -Force '$Script:RiskNoXControl'
                    & '$Script:RiskNoXControl' -Action start
"@
                
                $tempScript = Join-Path $env:TEMP "risknox_start_temp.ps1"
                $controlScript | Set-Content -Path $tempScript -Force
                
                $startArgs = @(
                    "-NoProfile"
                    "-ExecutionPolicy", "Bypass"
                    "-File", $tempScript
                )
                
                Write-AutoStartupLog "Executing RiskNoX fallback start: pwsh.exe $($startArgs -join ' ')" "DEBUG"
                
                $process = Start-Process -FilePath "pwsh.exe" -ArgumentList $startArgs -WorkingDirectory $Script:AgentPath -WindowStyle Hidden -PassThru
                
                # Don't wait indefinitely - give it 30 seconds max
                $timeout = 30
                $waited = 0
                while (!$process.HasExited -and $waited -lt $timeout) {
                    Start-Sleep -Seconds 1
                    $waited++
                }
                
                # Force kill if still running after timeout
                if (!$process.HasExited) {
                    Write-AutoStartupLog "RiskNoX start process timeout, terminating..." "WARN"
                    $process.Kill()
                }
                
                # Clean up temp script
                Remove-Item -Path $tempScript -Force -ErrorAction SilentlyContinue
                
                # Wait for RiskNoX agent to fully start
                Start-Sleep -Seconds 5
                
                # Verify RiskNoX agent started
                $newStatus = Get-RiskNoXAgentStatus
                if ($newStatus.Running -and $newStatus.FromWorkspace) {
                    Write-AutoStartupLog "RiskNoX Agent started successfully (PID: $($newStatus.ProcessId))" "SUCCESS"
                    Write-EventLog "RiskNoX Security Agent started successfully" "Information"
                    return $true
                } else {
                    Write-AutoStartupLog "RiskNoX Agent start command completed but agent is not running" "WARN"
                }
            }
        }
        catch {
            Write-AutoStartupLog "Error during RiskNoX Agent startup attempt $attempt`: $($_.Exception.Message)" "ERROR"
        }
        
        if ($attempt -lt $MaxRetries) {
            $delay = $Script:WatchdogConfig.RetryDelay
            Write-AutoStartupLog "Waiting $delay seconds before RiskNoX Agent retry..." "INFO"
            Start-Sleep -Seconds $delay
        }
    }
    
    Write-AutoStartupLog "Failed to start RiskNoX Agent after $MaxRetries attempts" "ERROR"
    Write-EventLog "Failed to start RiskNoX Security Agent after $MaxRetries attempts" "Warning"
    return $false
}

function Start-AllServices {
    Write-AutoStartupLog "Starting all monitoring and security services..." "INFO"
    
    $servicesStarted = $true
    
    for ($attempt = 1; $attempt -le $Script:WatchdogConfig.StartupRetries; $attempt++) {
        Write-AutoStartupLog "Startup attempt $attempt/$($Script:WatchdogConfig.StartupRetries)" "INFO"
        
        # Initialize variables to track individual service startup success
        $monitoringStarted = $false
        $riskNoXStarted = $false
        
        try {
            # Start both agents in parallel using background jobs for faster startup
            Write-AutoStartupLog "Starting Monitoring Agent and RiskNoX Agent in parallel..." "INFO"
            
            # Create background job for Monitoring Agent startup
            $monitoringJob = Start-Job -ScriptBlock {
                param($AgentPath, $ControlScript)
                
                # Function to start monitoring agent (copied into job context)
                function Start-MonitoringAgentJob {
                    try {
                        # Check if already running first
                        $processes = Get-Process "monitoring-agent" -ErrorAction SilentlyContinue | 
                            Where-Object { $_.Path -like "*$AgentPath*" }
                        
                        if ($processes) {
                            return @{ Success = $true; Message = "Already running"; PID = $processes[0].Id }
                        }
                        
                        # Start the agent
                        $startArgs = @(
                            "-NoProfile"
                            "-ExecutionPolicy", "Bypass"
                            "-File", $ControlScript
                            "start"
                        )
                        
                        $process = Start-Process -FilePath "pwsh.exe" -ArgumentList $startArgs -WorkingDirectory $AgentPath -WindowStyle Hidden -PassThru
                        $processCompleted = $process.WaitForExit(90000) # 90 seconds timeout
                        
                        if (!$processCompleted) {
                            try { $process.Kill() } catch { }
                            return @{ Success = $false; Message = "Timeout"; PID = $null }
                        }
                        
                        if ($process.ExitCode -eq 0) {
                            # Wait and verify startup
                            Start-Sleep -Seconds 3
                            for ($i = 1; $i -le 6; $i++) {
                                Start-Sleep -Seconds 2
                                $newProcesses = Get-Process "monitoring-agent" -ErrorAction SilentlyContinue | 
                                    Where-Object { $_.Path -like "*$AgentPath*" }
                                if ($newProcesses) {
                                    return @{ Success = $true; Message = "Started successfully"; PID = $newProcesses[0].Id }
                                }
                            }
                            return @{ Success = $false; Message = "Failed to verify startup"; PID = $null }
                        } else {
                            return @{ Success = $false; Message = "Start command failed"; PID = $null }
                        }
                    }
                    catch {
                        return @{ Success = $false; Message = $_.Exception.Message; PID = $null }
                    }
                }
                
                return Start-MonitoringAgentJob
            } -ArgumentList $Script:AgentPath, $Script:ControlScript
            
            # Create background job for RiskNoX Agent startup
            $riskNoXJob = Start-Job -ScriptBlock {
                param($AgentPath, $RiskNoXControl)
                
                # Function to start RiskNoX agent (copied into job context)
                function Start-RiskNoXAgentJob {
                    try {
                        # Check if already running first
                        $processes = Get-Process python -ErrorAction SilentlyContinue | 
                            Where-Object { 
                                try {
                                    $cmdLine = (Get-CimInstance -ClassName Win32_Process -Filter "ProcessId = $($_.Id)" -ErrorAction SilentlyContinue).CommandLine
                                    return ($cmdLine -like "*backend_server.py*" -and $cmdLine -like "*$AgentPath*")
                                } catch { return $false }
                            }
                        
                        if ($processes) {
                            return @{ Success = $true; Message = "Already running"; PID = $processes[0].Id }
                        }
                        
                        # Start RiskNoX agent
                        $startArgs = @(
                            "-NoProfile"
                            "-ExecutionPolicy", "Bypass"
                            "-File", $RiskNoXControl
                            "-Action", "start"
                        )
                        
                        $process = Start-Process -FilePath "pwsh.exe" -ArgumentList $startArgs -WorkingDirectory $AgentPath -WindowStyle Hidden -PassThru
                        $processCompleted = $process.WaitForExit(45000) # 45 seconds timeout
                        
                        if (!$processCompleted) {
                            # Don't kill - RiskNoX might still be starting
                        }
                        
                        # Wait and verify startup
                        Start-Sleep -Seconds 3
                        for ($i = 1; $i -le 8; $i++) {
                            Start-Sleep -Seconds 2
                            $newProcesses = Get-Process python -ErrorAction SilentlyContinue | 
                                Where-Object { 
                                    try {
                                        $cmdLine = (Get-CimInstance -ClassName Win32_Process -Filter "ProcessId = $($_.Id)" -ErrorAction SilentlyContinue).CommandLine
                                        return ($cmdLine -like "*backend_server.py*" -and $cmdLine -like "*$AgentPath*")
                                    } catch { return $false }
                                }
                            if ($newProcesses) {
                                return @{ Success = $true; Message = "Started successfully"; PID = $newProcesses[0].Id }
                            }
                        }
                        return @{ Success = $false; Message = "Failed to verify startup"; PID = $null }
                    }
                    catch {
                        return @{ Success = $false; Message = $_.Exception.Message; PID = $null }
                    }
                }
                
                return Start-RiskNoXAgentJob
            } -ArgumentList $Script:AgentPath, $Script:RiskNoXControl
            
            Write-AutoStartupLog "Both agents starting in parallel..." "INFO"
            
            # Wait for both jobs to complete with timeout (max 2 minutes total)
            $timeout = 120
            $startTime = Get-Date
            $monitoringResult = $null
            $riskNoXResult = $null
            
            while (((Get-Date) - $startTime).TotalSeconds -lt $timeout) {
                # Check monitoring job
                if ($monitoringJob.State -eq 'Completed' -and $monitoringResult -eq $null) {
                    $monitoringResult = Receive-Job -Job $monitoringJob
                    Write-AutoStartupLog "Monitoring Agent job completed: $($monitoringResult.Message)" "INFO"
                    $monitoringStarted = $monitoringResult.Success
                }
                
                # Check RiskNoX job
                if ($riskNoXJob.State -eq 'Completed' -and $riskNoXResult -eq $null) {
                    $riskNoXResult = Receive-Job -Job $riskNoXJob
                    Write-AutoStartupLog "RiskNoX Agent job completed: $($riskNoXResult.Message)" "INFO"
                    $riskNoXStarted = $riskNoXResult.Success
                }
                
                # If both completed, break
                if ($monitoringResult -ne $null -and $riskNoXResult -ne $null) {
                    break
                }
                
                Start-Sleep -Seconds 2
            }
            
            # Clean up jobs
            if ($monitoringJob.State -ne 'Completed') {
                Write-AutoStartupLog "Monitoring Agent job timeout, stopping..." "WARN"
                Stop-Job -Job $monitoringJob
                $monitoringStarted = $false
            }
            if ($riskNoXJob.State -ne 'Completed') {
                Write-AutoStartupLog "RiskNoX Agent job timeout, stopping..." "WARN"
                Stop-Job -Job $riskNoXJob
                $riskNoXStarted = $false
            }
            
            Remove-Job -Job $monitoringJob -Force
            Remove-Job -Job $riskNoXJob -Force
            
            # Log final results
            if ($monitoringResult) {
                if ($monitoringStarted) {
                    Write-AutoStartupLog "Monitoring Agent started successfully (PID: $($monitoringResult.PID))" "SUCCESS"
                } else {
                    Write-AutoStartupLog "Monitoring Agent failed to start: $($monitoringResult.Message)" "ERROR"
                }
            }
            
            if ($riskNoXResult) {
                if ($riskNoXStarted) {
                    Write-AutoStartupLog "RiskNoX Agent started successfully (PID: $($riskNoXResult.PID))" "SUCCESS"
                } else {
                    Write-AutoStartupLog "RiskNoX Agent failed to start: $($riskNoXResult.Message)" "ERROR"
                }
            }
            
            Write-AutoStartupLog "Parallel startup completed. Monitoring: $monitoringStarted, RiskNoX: $riskNoXStarted" "DEBUG"
            
            # If both agents started successfully, do quick verification and exit
            if ($monitoringStarted -and $riskNoXStarted) {
                Write-AutoStartupLog "Both agents started successfully in parallel - performing quick verification..." "INFO"
                Start-Sleep -Seconds 3
                
                # Quick status check
                try {
                    $agentStatus = Get-MonitoringAgentStatus
                    $riskNoXStatus = Get-RiskNoXAgentStatus
                    $suricataStatus = Get-SuricataStatus
                    
                    if ($agentStatus.Running -and $riskNoXStatus.Running) {
                        Write-AutoStartupLog "Quick verification successful - all services operational" "SUCCESS"
                        Write-AutoStartupLog "  - Monitoring Agent: Running (PID: $($agentStatus.ProcessId))" "SUCCESS"
                        if ($suricataStatus.Available -and $suricataStatus.Running) {
                            Write-AutoStartupLog "  - Suricata IDS: Running (PID: $($suricataStatus.ProcessId))" "SUCCESS"
                        }
                        Write-AutoStartupLog "  - RiskNoX Agent: Running (PID: $($riskNoXStatus.ProcessId))" "SUCCESS"
                        Write-EventLog "All monitoring and security services started successfully via parallel startup" "Information"
                        return $true
                    }
                }
                catch {
                    Write-AutoStartupLog "Quick verification failed, proceeding to full verification: $($_.Exception.Message)" "WARN"
                }
            }
            
            # Wait for all services to stabilize
            Start-Sleep -Seconds 5
            
            # Verify all services are running with timeout
            Write-AutoStartupLog "Verifying service status..." "DEBUG"
            try {
                $agentStatus = Get-MonitoringAgentStatus
                Write-AutoStartupLog "Got Monitoring Agent status" "DEBUG"
                $suricataStatus = Get-SuricataStatus
                Write-AutoStartupLog "Got Suricata status" "DEBUG"
                $riskNoXStatus = Get-RiskNoXAgentStatus
                Write-AutoStartupLog "Got RiskNoX status" "DEBUG"
                Write-AutoStartupLog "Status check completed" "DEBUG"
            }
            catch {
                Write-AutoStartupLog "Error during status check: $($_.Exception.Message)" "ERROR"
                throw
            }
            
            try {
                $agentRunning = $agentStatus.Running -and $agentStatus.FromWorkspace
                $suricataRunning = (!$suricataStatus.Available) -or ($suricataStatus.Running -and $suricataStatus.FromWorkspace)
                $riskNoXRunning = (!$riskNoXStatus.Available) -or ($riskNoXStatus.Running -and $riskNoXStatus.FromWorkspace)
                
                Write-AutoStartupLog "Service states - Agent: $agentRunning, Suricata: $suricataRunning, RiskNoX: $riskNoXRunning" "DEBUG"
            }
            catch {
                Write-AutoStartupLog "Error evaluating service states: $($_.Exception.Message)" "ERROR"
                throw
            }
            
            # Consider startup successful if at least the monitoring agent is running
            # and all available services were attempted to be started
            $startupSuccessful = $agentRunning -and $suricataRunning -and $riskNoXRunning
            
            if ($startupSuccessful) {
                Write-AutoStartupLog "All services started successfully" "SUCCESS"
                Write-AutoStartupLog "  - Monitoring Agent: Running (PID: $($agentStatus.ProcessId))" "SUCCESS"
                if ($suricataStatus.Available) {
                    Write-AutoStartupLog "  - Suricata IDS: Running (PID: $($suricataStatus.ProcessId))" "SUCCESS"
                }
                if ($riskNoXStatus.Available) {
                    Write-AutoStartupLog "  - RiskNoX Agent: Running (PID: $($riskNoXStatus.ProcessId))" "SUCCESS"
                }
                Write-EventLog "All monitoring and security services started successfully" "Information"
                return $true
            } else {
                # For a more lenient approach, if monitoring agent is running and RiskNoX was attempted,
                # consider it a partial success and don't retry unless this is the first attempt
                $partialSuccess = $agentRunning -and ($attempt -gt 1 -or $riskNoXStarted -or !$riskNoXStatus.Available)
                
                Write-AutoStartupLog "Service startup status:" "WARN"
                Write-AutoStartupLog "  - Monitoring Agent: $(if ($agentRunning) { 'Running' } else { 'Failed' })" "WARN"
                Write-AutoStartupLog "  - Suricata IDS: $(if ($suricataRunning) { 'Running' } else { 'Failed' })" "WARN"
                Write-AutoStartupLog "  - RiskNoX Agent: $(if ($riskNoXRunning) { 'Running' } else { 'Failed' })" "WARN"
                
                if ($partialSuccess) {
                    Write-AutoStartupLog "Partial startup success achieved - continuing with available services" "INFO"
                    return $true
                } else {
                    $servicesStarted = $false
                }
            }
        }
        catch {
            Write-AutoStartupLog "Error during startup attempt $attempt`: $($_.Exception.Message)" "ERROR"
            Write-AutoStartupLog "Error details: $($_.Exception.GetType().FullName)" "ERROR"
            Write-AutoStartupLog "Stack trace: $($_.ScriptStackTrace)" "DEBUG"
            $servicesStarted = $false
        }
        
        if ($attempt -lt $Script:WatchdogConfig.StartupRetries) {
            Write-AutoStartupLog "Waiting $($Script:WatchdogConfig.RetryDelay) seconds before retry..." "INFO"
            Start-Sleep -Seconds $Script:WatchdogConfig.RetryDelay
        }
    }
    
    if (!$servicesStarted) {
        Write-AutoStartupLog "Failed to start all services after $($Script:WatchdogConfig.StartupRetries) attempts" "ERROR"
        Write-EventLog "Failed to start all monitoring and security services" "Error"
    }
    
    return $servicesStarted
}
#endregion

#region Watchdog Functions
function Start-WatchdogService {
    param([int]$DurationMinutes = 0)
    
    Write-AutoStartupLog "Starting watchdog service..." "INFO"
    Write-EventLog "Monitoring Agent Watchdog Service started" "Information"
    
    # Save watchdog PID
    try {
        $currentPid = [System.Diagnostics.Process]::GetCurrentProcess().Id
        Set-Content -Path $Script:WatchdogPidFile -Value $currentPid -Force
        Write-AutoStartupLog "Watchdog PID ($currentPid) saved to $Script:WatchdogPidFile" "DEBUG"
    }
    catch {
        Write-AutoStartupLog "Failed to save watchdog PID: $($_.Exception.Message)" "WARN"
    }
    
    $Script:WatchdogRunning = $true
    $startTime = Get-Date
    $checkCount = 0
    
    # Initialize restart tracking
    $Script:LastRestartTime["MonitoringAgent"] = Get-Date
    $Script:LastRestartTime["Suricata"] = Get-Date
    $Script:LastRestartTime["RiskNoXAgent"] = Get-Date
    $Script:RestartCounts["MonitoringAgent"] = 0
    $Script:RestartCounts["Suricata"] = 0
    $Script:RestartCounts["RiskNoXAgent"] = 0
    
    Write-AutoStartupLog "Watchdog monitoring started (Duration: $(if ($DurationMinutes -gt 0) { "$DurationMinutes minutes" } else { "infinite" }))" "SUCCESS"
    
    while ($Script:WatchdogRunning) {
        $checkCount++
        $currentTime = Get-Date
        
        # Check if we should stop (duration limit)
        if ($DurationMinutes -gt 0 -and ($currentTime - $startTime).TotalMinutes -ge $DurationMinutes) {
            Write-AutoStartupLog "Watchdog duration limit reached ($DurationMinutes minutes)" "INFO"
            break
        }
        
        Write-AutoStartupLog "Watchdog check #$checkCount" "DEBUG"
        
        # Monitor Monitoring Agent
        if (!(Test-ServiceHealth -ServiceName "MonitoringAgent")) {
            Write-AutoStartupLog "Monitoring Agent health check failed" "WARN"
            
            if (Test-RestartAllowed -ServiceName "MonitoringAgent") {
                Write-AutoStartupLog "Attempting to restart Monitoring Agent..." "INFO"
                
                if (Start-MonitoringAgentWithRetry -MaxRetries 2) {
                    $Script:LastRestartTime["MonitoringAgent"] = $currentTime
                    $Script:RestartCounts["MonitoringAgent"]++
                    Write-AutoStartupLog "Monitoring Agent restarted successfully by watchdog" "SUCCESS"
                    Write-EventLog "Monitoring Agent was restarted by watchdog service" "Warning"
                } else {
                    Write-AutoStartupLog "Watchdog failed to restart Monitoring Agent" "ERROR"
                    Write-EventLog "Watchdog failed to restart Monitoring Agent" "Error"
                }
            } else {
                Write-AutoStartupLog "Restart not allowed for Monitoring Agent (cooldown or max attempts)" "WARN"
            }
        }
        
        # Monitor Suricata (if available)
        $suricataStatus = Get-SuricataStatus
        if ($suricataStatus.Available) {
            if (!(Test-ServiceHealth -ServiceName "Suricata")) {
                Write-AutoStartupLog "Suricata health check failed" "WARN"
                
                if (Test-RestartAllowed -ServiceName "Suricata") {
                    Write-AutoStartupLog "Attempting to restart Suricata..." "INFO"
                    
                    if (Start-SuricataWithRetry -MaxRetries 2) {
                        $Script:LastRestartTime["Suricata"] = $currentTime
                        $Script:RestartCounts["Suricata"]++
                        Write-AutoStartupLog "Suricata restarted successfully by watchdog" "SUCCESS"
                        Write-EventLog "Suricata Network IDS was restarted by watchdog service" "Warning"
                    } else {
                        Write-AutoStartupLog "Watchdog failed to restart Suricata" "ERROR"
                        Write-EventLog "Watchdog failed to restart Suricata Network IDS" "Error"
                    }
                } else {
                    Write-AutoStartupLog "Restart not allowed for Suricata (cooldown or max attempts)" "WARN"
                }
            }
        }
        
        # Monitor RiskNoX Agent (if available)
        $riskNoXStatus = Get-RiskNoXAgentStatus
        if ($riskNoXStatus.Available) {
            if (!(Test-ServiceHealth -ServiceName "RiskNoXAgent")) {
                Write-AutoStartupLog "RiskNoX Agent health check failed" "WARN"
                
                if (Test-RestartAllowed -ServiceName "RiskNoXAgent") {
                    Write-AutoStartupLog "Attempting to restart RiskNoX Agent..." "INFO"
                    
                    if (Start-RiskNoXAgentWithRetry -MaxRetries 2) {
                        $Script:LastRestartTime["RiskNoXAgent"] = $currentTime
                        $Script:RestartCounts["RiskNoXAgent"]++
                        Write-AutoStartupLog "RiskNoX Agent restarted successfully by watchdog" "SUCCESS"
                        Write-EventLog "RiskNoX Security Agent was restarted by watchdog service" "Warning"
                    } else {
                        Write-AutoStartupLog "Watchdog failed to restart RiskNoX Agent" "ERROR"
                        Write-EventLog "Watchdog failed to restart RiskNoX Security Agent" "Error"
                    }
                } else {
                    Write-AutoStartupLog "Restart not allowed for RiskNoX Agent (cooldown or max attempts)" "WARN"
                }
            }
        }
        
        # Reset hourly restart counters
        Reset-HourlyCounters
        
        # Sleep until next check
        Start-Sleep -Seconds $Script:WatchdogConfig.CheckInterval
    }
    
    Write-AutoStartupLog "Watchdog service stopped" "INFO"
    Write-EventLog "Monitoring Agent Watchdog Service stopped" "Information"
    
    # Clean up watchdog PID file
    try {
        Remove-Item -Path $Script:WatchdogPidFile -Force -ErrorAction SilentlyContinue
    }
    catch {
        # Continue silently
    }
}

function Test-RestartAllowed {
    param([string]$ServiceName)
    
    $currentTime = Get-Date
    $lastRestart = $Script:LastRestartTime[$ServiceName]
    $restartCount = $Script:RestartCounts[$ServiceName]
    
    # Check cooldown period
    $timeSinceLastRestart = ($currentTime - $lastRestart).TotalSeconds
    if ($timeSinceLastRestart -lt $Script:WatchdogConfig.RestartCooldown) {
        Write-AutoStartupLog "Service $ServiceName is in restart cooldown ($(($Script:WatchdogConfig.RestartCooldown - $timeSinceLastRestart).ToString('F0')) seconds remaining)" "DEBUG"
        return $false
    }
    
    # Check maximum restart attempts per hour
    if ($restartCount -ge $Script:WatchdogConfig.MaxRestartAttempts) {
        Write-AutoStartupLog "Service $ServiceName has reached maximum restart attempts ($restartCount) for this hour" "WARN"
        return $false
    }
    
    return $true
}

function Reset-HourlyCounters {
    $currentTime = Get-Date
    
    foreach ($serviceName in @("MonitoringAgent", "Suricata", "RiskNoXAgent")) {
        if ($Script:LastRestartTime.ContainsKey($serviceName)) {
            $lastRestart = $Script:LastRestartTime[$serviceName]
            if (($currentTime - $lastRestart).TotalHours -ge 1) {
                $Script:RestartCounts[$serviceName] = 0
                Write-AutoStartupLog "Reset restart counter for $serviceName" "DEBUG"
            }
        }
    }
}

function Stop-WatchdogService {
    Write-AutoStartupLog "Stopping watchdog service..." "INFO"
    $Script:WatchdogRunning = $false
}

function Test-WatchdogRunning {
    try {
        if (Test-Path $Script:WatchdogPidFile) {
            $watchdogPid = Get-Content -Path $Script:WatchdogPidFile -ErrorAction SilentlyContinue
            if ($watchdogPid) {
                $process = Get-Process -Id $watchdogPid -ErrorAction SilentlyContinue
                if ($process -and $process.ProcessName -eq "pwsh") {
                    return @{
                        Running = $true
                        ProcessId = $watchdogPid
                        StartTime = $process.StartTime
                    }
                }
            }
        }
    }
    catch {
        # Continue silently
    }
    
    return @{
        Running = $false
        ProcessId = $null
        StartTime = $null
    }
}
#endregion

#region Startup Mode Functions
function Start-SystemBootup {
    Write-AutoStartupLog "=== SYSTEM BOOT STARTUP MODE ===" "INFO"
    
    $uptime = Get-SystemUptime
    Write-AutoStartupLog "System uptime: $($uptime.ToString('hh\:mm\:ss'))" "INFO"
    
    # Wait for system to be ready
    if ($uptime.TotalMinutes -lt 2) {
        Write-AutoStartupLog "Recent boot detected, waiting for system readiness..." "INFO"
        Start-Sleep -Seconds $Script:StartupDelays.SystemBoot
        
        if (!(Wait-ForSystemReady -MaxWaitSeconds 300)) {
            Write-AutoStartupLog "System readiness timeout, proceeding with startup anyway..." "WARN"
        }
    }
    
    # Start services
    $success = Start-AllServices
    
    if ($success) {
        Write-AutoStartupLog "System boot startup completed successfully" "SUCCESS"
        
        # Start watchdog if requested
        if (!$NoWait) {
            Write-AutoStartupLog "Starting watchdog service..." "INFO"
            Start-WatchdogService -DurationMinutes $Duration
        }
    } else {
        Write-AutoStartupLog "System boot startup failed" "ERROR"
    }
    
    return $success
}

function Start-UserLogon {
    Write-AutoStartupLog "=== USER LOGON STARTUP MODE ===" "INFO"
    
    # Brief delay for user logon
    Start-Sleep -Seconds $Script:StartupDelays.UserLogon
    
    # Check if services are already running (might have been started by boot trigger)
    $agentStatus = Get-MonitoringAgentStatus
    $suricataStatus = Get-SuricataStatus
    $riskNoXStatus = Get-RiskNoXAgentStatus
    
    # Log current service states for debugging
    Write-AutoStartupLog "Current service states:" "DEBUG"
    Write-AutoStartupLog "  - Monitoring Agent: Available=$($agentStatus.Available), Running=$($agentStatus.Running)" "DEBUG"
    Write-AutoStartupLog "  - Suricata: Available=$($suricataStatus.Available), Running=$($suricataStatus.Running)" "DEBUG"
    Write-AutoStartupLog "  - RiskNoX Agent: Available=$($riskNoXStatus.Available), Running=$($riskNoXStatus.Running)" "DEBUG"
    
    # Only skip startup if ALL available services are running and properly responding
    $allServicesRunning = $agentStatus.Running -and $agentStatus.FromWorkspace -and
                         (!$suricataStatus.Available -or ($suricataStatus.Running -and $suricataStatus.FromWorkspace)) -and
                         (!$riskNoXStatus.Available -or ($riskNoXStatus.Running -and $riskNoXStatus.FromWorkspace))
    
    if ($allServicesRunning) {
        Write-AutoStartupLog "All services already running from boot startup" "INFO"
        Write-AutoStartupLog "  - Monitoring Agent: Running (PID: $($agentStatus.ProcessId))" "INFO"
        if ($suricataStatus.Available -and $suricataStatus.Running) {
            Write-AutoStartupLog "  - Suricata: Running (PID: $($suricataStatus.ProcessId))" "INFO"
        }
        if ($riskNoXStatus.Available -and $riskNoXStatus.Running) {
            Write-AutoStartupLog "  - RiskNoX Agent: Running (PID: $($riskNoXStatus.ProcessId))" "INFO"
        }
        return $true
    } else {
        # Log why we're proceeding with startup
        Write-AutoStartupLog "Not all services are running properly, proceeding with startup..." "INFO"
        if (!$agentStatus.Running -or !$agentStatus.FromWorkspace) {
            Write-AutoStartupLog "  - Monitoring Agent needs to be started" "INFO"
        }
        if ($suricataStatus.Available -and (!$suricataStatus.Running -or !$suricataStatus.FromWorkspace)) {
            Write-AutoStartupLog "  - Suricata needs to be started" "INFO"
        }
        if ($riskNoXStatus.Available -and (!$riskNoXStatus.Running -or !$riskNoXStatus.FromWorkspace)) {
            Write-AutoStartupLog "  - RiskNoX Agent needs to be started" "INFO"
        }
    }
    
    # Start services
    $success = Start-AllServices
    
    if ($success) {
        Write-AutoStartupLog "User logon startup completed successfully" "SUCCESS"
    } else {
        Write-AutoStartupLog "User logon startup failed" "ERROR"
    }
    
    return $success
}

function Start-TestMode {
    Write-AutoStartupLog "=== TEST MODE ===" "INFO"
    
    # Check current status
    $agentStatus = Get-MonitoringAgentStatus
    $suricataStatus = Get-SuricataStatus
    $riskNoXStatus = Get-RiskNoXAgentStatus
    $watchdogStatus = Test-WatchdogRunning
    
    Write-AutoStartupLog "Current Status:" "INFO"
    Write-AutoStartupLog "  Monitoring Agent: $(if ($agentStatus.Running) { "Running (PID: $($agentStatus.ProcessId))" } else { "Stopped" })" "INFO"
    Write-AutoStartupLog "  Suricata: $(if ($suricataStatus.Available) { if ($suricataStatus.Running) { "Running (PID: $($suricataStatus.ProcessId))" } else { "Stopped" } } else { "Not Available" })" "INFO"
    Write-AutoStartupLog "  RiskNoX Agent: $(if ($riskNoXStatus.Available) { if ($riskNoXStatus.Running) { "Running (PID: $($riskNoXStatus.ProcessId))" } else { "Stopped" } } else { "Not Available" })" "INFO"
    Write-AutoStartupLog "  Watchdog: $(if ($watchdogStatus.Running) { "Running (PID: $($watchdogStatus.ProcessId))" } else { "Stopped" })" "INFO"
    
    # Test service health
    Write-AutoStartupLog "Testing service health..." "INFO"
    $agentHealthy = Test-ServiceHealth -ServiceName "MonitoringAgent"
    Write-AutoStartupLog "  Monitoring Agent Health: $(if ($agentHealthy) { "HEALTHY" } else { "UNHEALTHY" })" "INFO"
    
    if ($suricataStatus.Available) {
        $suricataHealthy = Test-ServiceHealth -ServiceName "Suricata"
        Write-AutoStartupLog "  Suricata Health: $(if ($suricataHealthy) { "HEALTHY" } else { "UNHEALTHY" })" "INFO"
    }
    
    if ($riskNoXStatus.Available) {
        $riskNoXHealthy = Test-ServiceHealth -ServiceName "RiskNoXAgent"
        Write-AutoStartupLog "  RiskNoX Agent Health: $(if ($riskNoXHealthy) { "HEALTHY" } else { "UNHEALTHY" })" "INFO"
    }
    
    # Test network connectivity
    $networkConnected = Test-NetworkConnectivity
    Write-AutoStartupLog "  Network Connectivity: $(if ($networkConnected) { "CONNECTED" } else { "DISCONNECTED" })" "INFO"
    
    Write-AutoStartupLog "Test mode completed" "SUCCESS"
    return $true
}
#endregion

#region Main Execution
function Main {
    # Ensure running as administrator
    if (!(Test-AdminRights)) {
        Write-AutoStartupLog "This script requires administrator privileges" "ERROR"
        exit 1
    }
    
    # Ensure required files exist
    if (!(Test-Path $Script:AgentExe)) {
        Write-AutoStartupLog "Agent executable not found: $Script:AgentExe" "ERROR"
        exit 1
    }
    
    if (!(Test-Path $Script:ControlScript)) {
        Write-AutoStartupLog "Control script not found: $Script:ControlScript" "ERROR"
        exit 1
    }
    
    # RiskNoX control script is optional - log warning if not found but don't exit
    if (!(Test-Path $Script:RiskNoXControl)) {
        Write-AutoStartupLog "RiskNoX control script not found: $Script:RiskNoXControl (RiskNoX features will be unavailable)" "WARN"
    }
    
    Write-AutoStartupLog "Monitoring Agent Auto-Startup v2.0.0 - Mode: $Mode" "INFO"
    Write-AutoStartupLog "Working Directory: $Script:AgentPath" "DEBUG"
    Write-AutoStartupLog "Command Line: $($MyInvocation.Line)" "DEBUG"
    
    try {
        switch ($Mode.ToLower()) {
            "startup" {
                # Determine startup type based on system uptime
                $uptime = Get-SystemUptime
                if ($uptime.TotalMinutes -lt 5) {
                    $result = Start-SystemBootup
                } else {
                    $result = Start-UserLogon
                }
                return $result
            }
            
            "watchdog" {
                Write-AutoStartupLog "=== WATCHDOG MODE ===" "INFO"
                $result = Start-WatchdogService -DurationMinutes $Duration
                return $result
            }
            
            "test" {
                $result = Start-TestMode
                return $result
            }
            
            default {
                Write-AutoStartupLog "Invalid mode: $Mode" "ERROR"
                return $false
            }
        }
    }
    catch {
        Write-AutoStartupLog "Fatal error in main execution: $($_.Exception.Message)" "ERROR"
        Write-EventLog "Fatal error in Monitoring Agent Auto-Startup: $($_.Exception.Message)" "Error"
        return $false
    }
}

# Handle Ctrl+C gracefully in watchdog mode
Register-EngineEvent -SourceIdentifier PowerShell.Exiting -Action {
    if ($Script:WatchdogRunning) {
        Write-AutoStartupLog "Received shutdown signal, stopping watchdog..." "INFO"
        Stop-WatchdogService
    }
}

# Execute main function
try {
    $result = Main
    Write-AutoStartupLog "Main function completed with result: $result" "DEBUG"
    if ($result) {
        Write-AutoStartupLog "Startup completed successfully - exiting" "INFO"
        exit 0
    } else {
        Write-AutoStartupLog "Startup completed with issues - exiting" "WARN"
        exit 1
    }
}
catch {
    Write-AutoStartupLog "Main function failed: $($_.Exception.Message)" "ERROR"
    exit 1
}
#endregion