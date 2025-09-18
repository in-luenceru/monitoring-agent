# Windows Monitoring Agent Enhanced Logging Script
# Handles advanced logging, alerting, and notification features
# Copyright (C) 2025, Monitoring Solutions Inc.

param(
    [string]$Action = "init",
    [string]$Message = "",
    [string]$Level = "INFO"
)

# Configuration
$script:AGENT_HOME = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$script:LOG_DIR = Join-Path $script:AGENT_HOME "logs"
$script:MAIN_LOG = Join-Path $script:LOG_DIR "monitoring-agent.log"
$script:ALERT_LOG = Join-Path $script:LOG_DIR "monitoring-alerts.log"
$script:HEALTH_LOG = Join-Path $script:LOG_DIR "monitoring-health.log"
$script:CONFIG_FILE = Join-Path $script:AGENT_HOME "etc\monitoring-alerts.conf"

# Ensure log directory exists
if (-not (Test-Path $script:LOG_DIR)) {
    New-Item -Path $script:LOG_DIR -ItemType Directory -Force | Out-Null
}

function Write-EnhancedLog {
    param(
        [string]$LogFile,
        [string]$Level,
        [string]$Message,
        [string]$Component = "LOGGING"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Component] [$Level] $Message"
    
    try {
        Add-Content -Path $LogFile -Value $logEntry -ErrorAction Stop
        
        # Also log to main log if not already logging there
        if ($LogFile -ne $script:MAIN_LOG) {
            Add-Content -Path $script:MAIN_LOG -Value $logEntry -ErrorAction SilentlyContinue
        }
    }
    catch {
        # Fallback to console
        Write-Host $logEntry
    }
}

function Initialize-LoggingConfig {
    Write-EnhancedLog $script:MAIN_LOG "INFO" "Initializing enhanced logging configuration"
    
    # Create default alert configuration if it doesn't exist
    if (-not (Test-Path $script:CONFIG_FILE)) {
        $defaultConfig = @"
# Monitoring Agent Alert Configuration
# This file configures alert levels and notification settings

[AlertLevels]
CRITICAL=email,syslog
ERROR=syslog
WARN=log
INFO=log
DEBUG=log

[EmailSettings]
Enabled=false
SMTPServer=
SMTPPort=587
Username=
Password=
From=monitoring-agent@localhost
To=admin@localhost

[SyslogSettings]
Enabled=true
Server=localhost
Port=514
Facility=16

[LogRotation]
Enabled=true
MaxSize=10MB
MaxFiles=5
CompressOld=true
"@
        
        try {
            $defaultConfig | Set-Content -Path $script:CONFIG_FILE -Encoding UTF8
            Write-EnhancedLog $script:MAIN_LOG "INFO" "Created default alert configuration: $script:CONFIG_FILE"
        }
        catch {
            Write-EnhancedLog $script:MAIN_LOG "WARN" "Failed to create alert configuration: $($_.Exception.Message)"
        }
    }
    
    # Initialize log files
    $logFiles = @($script:MAIN_LOG, $script:ALERT_LOG, $script:HEALTH_LOG)
    foreach ($logFile in $logFiles) {
        if (-not (Test-Path $logFile)) {
            try {
                "" | Set-Content -Path $logFile -Encoding UTF8
                Write-EnhancedLog $script:MAIN_LOG "DEBUG" "Initialized log file: $logFile"
            }
            catch {
                Write-Host "Failed to initialize log file: $logFile"
            }
        }
    }
}

function Send-Alert {
    param(
        [string]$Level,
        [string]$Message,
        [string]$Component = "MONITORING"
    )
    
    Write-EnhancedLog $script:ALERT_LOG $Level $Message $Component
    
    # TODO: Implement email/syslog alerting based on configuration
    # For now, just ensure it's logged prominently
    if ($Level -eq "CRITICAL" -or $Level -eq "ERROR") {
        $alertMessage = "ALERT [$Level] $Component`: $Message"
        Write-EnhancedLog $script:MAIN_LOG $Level $alertMessage "ALERT"
        
        # Also try to log to Windows Event Log
        try {
            $eventLogSource = "MonitoringAgent"
            if (-not [System.Diagnostics.EventLog]::SourceExists($eventLogSource)) {
                New-EventLog -LogName Application -Source $eventLogSource -ErrorAction SilentlyContinue
            }
            
            $eventType = if ($Level -eq "CRITICAL") { "Error" } elseif ($Level -eq "ERROR") { "Error" } else { "Warning" }
            Write-EventLog -LogName Application -Source $eventLogSource -EntryType $eventType -EventId 1001 -Message $alertMessage -ErrorAction SilentlyContinue
        }
        catch {
            # Ignore event log errors
        }
    }
}

function Write-HealthReport {
    param(
        [string]$Status,
        [string]$Details = ""
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $healthEntry = "[$timestamp] STATUS=$Status $Details"
    
    try {
        Add-Content -Path $script:HEALTH_LOG -Value $healthEntry -ErrorAction Stop
    }
    catch {
        Write-EnhancedLog $script:MAIN_LOG "WARN" "Failed to write health report: $($_.Exception.Message)"
    }
}

function Rotate-Logs {
    param([int]$MaxSizeMB = 10, [int]$MaxFiles = 5)
    
    $logFiles = @($script:MAIN_LOG, $script:ALERT_LOG, $script:HEALTH_LOG)
    
    foreach ($logFile in $logFiles) {
        if (Test-Path $logFile) {
            $fileInfo = Get-Item $logFile
            $fileSizeMB = [math]::Round($fileInfo.Length / 1MB, 2)
            
            if ($fileSizeMB -gt $MaxSizeMB) {
                Write-EnhancedLog $script:MAIN_LOG "INFO" "Rotating log file: $logFile (Size: ${fileSizeMB}MB)"
                
                try {
                    # Move existing rotated logs
                    for ($i = $MaxFiles - 1; $i -gt 0; $i--) {
                        $oldFile = "$logFile.$i"
                        $newFile = "$logFile.$($i + 1)"
                        
                        if (Test-Path $oldFile) {
                            if ($i -eq ($MaxFiles - 1)) {
                                # Delete the oldest file
                                Remove-Item $oldFile -Force
                            }
                            else {
                                Move-Item $oldFile $newFile -Force
                            }
                        }
                    }
                    
                    # Move current log to .1
                    Move-Item $logFile "$logFile.1" -Force
                    
                    # Create new empty log file
                    "" | Set-Content -Path $logFile -Encoding UTF8
                    
                    Write-EnhancedLog $script:MAIN_LOG "INFO" "Log rotation completed for: $logFile"
                }
                catch {
                    Write-EnhancedLog $script:MAIN_LOG "ERROR" "Failed to rotate log file $logFile`: $($_.Exception.Message)"
                }
            }
        }
    }
}

function Start-LoggingService {
    Write-EnhancedLog $script:MAIN_LOG "INFO" "Starting enhanced logging service"
    
    # Initialize configuration
    Initialize-LoggingConfig
    
    # Perform initial log rotation check
    Rotate-Logs
    
    Write-EnhancedLog $script:MAIN_LOG "INFO" "Enhanced logging service started successfully"
}

function Stop-LoggingService {
    Write-EnhancedLog $script:MAIN_LOG "INFO" "Stopping enhanced logging service"
}

# Main execution
switch ($Action.ToLower()) {
    "init" {
        Initialize-LoggingConfig
    }
    "init-config" {
        Initialize-LoggingConfig
    }
    "start" {
        Start-LoggingService
    }
    "stop" {
        Stop-LoggingService
    }
    "startup" {
        Send-Alert "INFO" $Message "STARTUP"
    }
    "shutdown" {
        Send-Alert "INFO" $Message "SHUTDOWN"
    }
    "alert" {
        Send-Alert $Level $Message "MONITORING"
    }
    "health" {
        Write-HealthReport $Level $Message
    }
    "rotate" {
        Rotate-Logs
    }
    default {
        Write-Host "Usage: monitoring-logging.ps1 [init|start|stop|startup|shutdown|alert|health|rotate]"
        exit 1
    }
}