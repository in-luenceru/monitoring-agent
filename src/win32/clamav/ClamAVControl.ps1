# ClamAV Control Script
# PowerShell script for managing ClamAV scans
# Copyright (C) 2026, Monitoring Solutions Inc.

param(
    [Parameter(Position=0)]
    [string]$Action,
   
    [Parameter(Position=1)]
    [string]$Param1,
   
    [Parameter(Position=2)]
    [int]$Param2
)

# Configuration
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$InstallDir = Split-Path -Parent $ScriptDir
$ClamAVDir = $ScriptDir
$DatabaseDir = Join-Path $ClamAVDir "database"
$LogDir = Join-Path $ClamAVDir "logs"
$ClamScan = Join-Path $ClamAVDir "clamscan.exe"
$FreshClam = Join-Path $ClamAVDir "freshclam.exe"
$ClamConf = Join-Path $ClamAVDir "clamscan.conf"
$FreshConf = Join-Path $ClamAVDir "freshclam.conf"
$ScanLog = Join-Path $LogDir "clamscan.log"
$UpdateLog = Join-Path $LogDir "freshclam.log"
$PidFile = Join-Path $LogDir "clamscan.pid"
$StatusFile = Join-Path $LogDir "clamscan_status.json"
$ScheduleConfig = Join-Path $ClamAVDir "clamav_schedule.conf"
$TaskName = "MonitoringAgent-ClamAV-AutoScan"

# Log levels
$LogLevelDebug = 0
$LogLevelInfo = 1
$LogLevelWarning = 2
$LogLevelError = 3
$CurrentLogLevel = $LogLevelInfo

# Ensure log directory exists
if (-not (Test-Path $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}

function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
   
    # Determine numeric level for filtering
    $numericLevel = switch ($Level.ToUpper()) {
        "DEBUG" { $LogLevelDebug }
        "INFO" { $LogLevelInfo }
        "WARNING" { $LogLevelWarning }
        "ERROR" { $LogLevelError }
        default { $LogLevelInfo }
    }
   
    # Skip if below current log level
    if ($numericLevel -lt $CurrentLogLevel) { return }
   
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    Add-Content -Path $ScanLog -Value $logMessage -ErrorAction SilentlyContinue
    Write-Output $logMessage
}

function Write-ScanStatus {
    param(
        [bool]$Scanning = $false,
        [string]$CurrentFolder = "",
        [int]$FilesScanned = 0,
        [int]$ThreatsFound = 0,
        [int]$ProgressPercent = 0,
        [string]$ScanType = "",
        [string]$Message = ""
    )
   
    $status = @{
        scanning = $Scanning
        current_folder = $CurrentFolder
        files_scanned = $FilesScanned
        threats_found = $ThreatsFound
        progress_percent = $ProgressPercent
        scan_type = $ScanType
        message = $Message
        timestamp = (Get-Date -Format "yyyy-MM-ddTHH:mm:ss")
    }
   
    $status | ConvertTo-Json | Set-Content -Path $StatusFile -Force -ErrorAction SilentlyContinue
}

function Clear-ScanStatus {
    if (Test-Path $StatusFile) {
        Remove-Item $StatusFile -Force -ErrorAction SilentlyContinue
    }
}

function Test-ScanRunning {
    # First check if our specific PID file points to a running clamscan
    if (Test-Path $PidFile) {
        $storedPid = Get-Content $PidFile -ErrorAction SilentlyContinue
        if ($storedPid) {
            try {
                $process = Get-Process -Id ([int]$storedPid) -ErrorAction SilentlyContinue
                if ($process -and $process.Name -match "clamscan") {
                    return $true
                }
            }
            catch {
                # Process not found - stale PID file
            }
        }
        # PID file exists but process not running - clean it up
        Remove-Item $PidFile -Force -ErrorAction SilentlyContinue
    }
   
    # Don't check for other clamscan processes - only our tracked one
    return $false
}

function Force-ClearScanLock {
    # Force clear any stale lock files at start of scan
    Write-Log "Clearing any stale scan locks" -Level "DEBUG"
   
    # Remove PID file
    if (Test-Path $PidFile) {
        Remove-Item $PidFile -Force -ErrorAction SilentlyContinue
    }
   
    # Clear status file
    if (Test-Path $StatusFile) {
        Remove-Item $StatusFile -Force -ErrorAction SilentlyContinue
    }
}

function Start-QuickScan {
    Write-Log "Quick Scan initiated" -Level "INFO"
   
    # Force clear stale locks first
    Force-ClearScanLock
   
    Write-Log "Checking for running scans..." -Level "DEBUG"
   
    if (Test-ScanRunning) {
        Write-Log "A scan is already in progress - aborting" -Level "ERROR"
        return $false
    }
   
    # Quick scan targets: Common threat locations
    $targets = @(
        "$env:WINDIR\Temp",
        "$env:TEMP",
        "$env:USERPROFILE\Downloads",
        "$env:USERPROFILE\Desktop",
        "$env:APPDATA",
        "$env:LOCALAPPDATA\Temp"
    )
   
    $validTargets = $targets | Where-Object { Test-Path $_ }
    Write-Log "Found $($validTargets.Count) valid scan targets" -Level "INFO"
   
    if ($validTargets.Count -eq 0) {
        Write-Log "No valid scan targets found - aborting" -Level "ERROR"
        return $false
    }
   
    # Log each target
    foreach ($target in $validTargets) {
        Write-Log "Target: $target" -Level "DEBUG"
    }
   
    $startTime = Get-Date
    $totalThreats = 0
    $totalFiles = 0
    $totalTargets = $validTargets.Count
    $currentTarget = 0
   
    try {
        Write-ScanStatus -Scanning $true -ScanType "Quick" -Message "Starting Quick Scan..."
       
        foreach ($target in $validTargets) {
            $currentTarget++
            $progressPercent = [int](($currentTarget / $totalTargets) * 100)
           
            Write-Log "Scanning: $target" -Level "INFO"
            Write-ScanStatus -Scanning $true -CurrentFolder $target -ProgressPercent $progressPercent -ScanType "Quick" -Message "Scanning folder $currentTarget of $totalTargets"
           
            # Build scan arguments - use verbose mode for detailed output
            $scanArgs = "--database=`"$DatabaseDir`" --log=`"$ScanLog`" --verbose --recursive --infected `"$target`""
           
            # Start the process and capture output
            $psi = New-Object System.Diagnostics.ProcessStartInfo
            $psi.FileName = $ClamScan
            $psi.Arguments = $scanArgs
            $psi.UseShellExecute = $false
            $psi.RedirectStandardOutput = $true
            $psi.RedirectStandardError = $true
            $psi.CreateNoWindow = $true
           
            $process = New-Object System.Diagnostics.Process
            $process.StartInfo = $psi
            $process.Start() | Out-Null
           
            # Store PID for tracking
            $process.Id | Out-File -FilePath $PidFile -Force
           
            # Wait for completion and capture output
            $stdout = $process.StandardOutput.ReadToEnd()
            $stderr = $process.StandardError.ReadToEnd()
            $process.WaitForExit()
           
            # Parse clamscan output for summary
            if ($stdout -match "Infected files:\s*(\d+)") {
                $infected = [int]$Matches[1]
                $totalThreats += $infected
                if ($infected -gt 0) {
                    Write-Log "Threats detected in: $target - $infected infected file(s)" -Level "WARNING"
                }
            }
            if ($stdout -match "Scanned files:\s*(\d+)") {
                $files = [int]$Matches[1]
                $totalFiles += $files
            }
           
            # Log any FOUND items for Wazuh to detect
            $stdout -split "`n" | Where-Object { $_ -match "FOUND" } | ForEach-Object {
                Write-Log "$_" -Level "WARNING"
            }
           
            Write-Log "Target $target complete - Exit code: $($process.ExitCode)" -Level "DEBUG"
        }
       
        # Clean up PID file
        Remove-Item $PidFile -Force -ErrorAction SilentlyContinue
       
        $elapsedTime = (Get-Date) - $startTime
        $elapsedSeconds = [int]$elapsedTime.TotalSeconds
       
        Write-Log "Quick Scan completed - Targets: $totalTargets, Files: $totalFiles, Threats: $totalThreats, Time: ${elapsedSeconds}s" -Level "INFO"
        Write-ScanStatus -Scanning $false -FilesScanned $totalFiles -ThreatsFound $totalThreats -ProgressPercent 100 -ScanType "Quick" -Message "Scan completed"
       
        if ($totalThreats -gt 0) {
            Write-Log "Quick Scan completed - $totalThreats threats detected! Check log for details." -Level "WARNING"
        } else {
            Write-Log "Quick Scan completed - No threats found" -Level "INFO"
        }
       
        return $true
    }
    catch {
        Write-Log "Quick Scan failed - $($_.Exception.Message)" -Level "ERROR"
        Remove-Item $PidFile -Force -ErrorAction SilentlyContinue
        Clear-ScanStatus
        return $false
    }
}

function Start-FullScan {
    Write-Log "Full Scan initiated" -Level "INFO"
   
    # Force clear stale locks first
    Force-ClearScanLock
   
    Write-Log "Checking for running scans..." -Level "DEBUG"
   
    if (Test-ScanRunning) {
        Write-Log "A scan is already in progress - aborting" -Level "ERROR"
        return $false
    }
   
    # Full scan: All fixed drives
    $drives = Get-WmiObject Win32_LogicalDisk | Where-Object { $_.DriveType -eq 3 } | Select-Object -ExpandProperty DeviceID
   
    if ($drives.Count -eq 0) {
        Write-Log "No fixed drives found - aborting" -Level "ERROR"
        return $false
    }
   
    Write-Log "Found $($drives.Count) fixed drives to scan" -Level "INFO"
    foreach ($d in $drives) { Write-Log "Drive: $d" -Level "DEBUG" }
   
    $startTime = Get-Date
    $totalThreats = 0
    $totalFiles = 0
    $totalDrives = $drives.Count
    $currentDrive = 0
   
    try {
        Write-ScanStatus -Scanning $true -ScanType "Full" -Message "Starting Full Scan..."
       
        foreach ($drive in $drives) {
            $currentDrive++
            $progressPercent = [int](($currentDrive / $totalDrives) * 100)
           
            Write-Log "Scanning drive: $drive ($currentDrive of $totalDrives)" -Level "INFO"
            Write-ScanStatus -Scanning $true -CurrentFolder "$drive\" -ProgressPercent $progressPercent -ScanType "Full" -Message "Scanning drive $currentDrive of $totalDrives"
           
            # Build scan arguments with verbose mode
            $scanArgs = "--database=`"$DatabaseDir`" --log=`"$ScanLog`" --verbose --recursive --infected --exclude-dir=`"Windows\\WinSxS`" --exclude-dir=`"Windows\\assembly`" `"$drive\`""
           
            # Start the process and capture output
            $psi = New-Object System.Diagnostics.ProcessStartInfo
            $psi.FileName = $ClamScan
            $psi.Arguments = $scanArgs
            $psi.UseShellExecute = $false
            $psi.RedirectStandardOutput = $true
            $psi.RedirectStandardError = $true
            $psi.CreateNoWindow = $true
           
            $process = New-Object System.Diagnostics.Process
            $process.StartInfo = $psi
            $process.Start() | Out-Null
           
            # Store PID for tracking
            $process.Id | Out-File -FilePath $PidFile -Force
           
            # Wait for completion and capture output
            $stdout = $process.StandardOutput.ReadToEnd()
            $stderr = $process.StandardError.ReadToEnd()
            $process.WaitForExit()
           
            # Parse clamscan output for summary
            if ($stdout -match "Infected files:\s*(\d+)") {
                $infected = [int]$Matches[1]
                $totalThreats += $infected
                if ($infected -gt 0) {
                    Write-Log "Threats detected on drive $drive - $infected infected file(s)" -Level "WARNING"
                }
            }
            if ($stdout -match "Scanned files:\s*(\d+)") {
                $files = [int]$Matches[1]
                $totalFiles += $files
            }
           
            # Log any FOUND items for Wazuh to detect
            $stdout -split "`n" | Where-Object { $_ -match "FOUND" } | ForEach-Object {
                Write-Log "$_" -Level "WARNING"
            }
           
            if ($process.ExitCode -eq 0) {
                Write-Log "Drive $drive scan completed - no threats" -Level "INFO"
            } else {
                Write-Log "Drive $drive scan completed with exit code: $($process.ExitCode)" -Level "DEBUG"
            }
        }
       
        # Clean up PID file
        Remove-Item $PidFile -Force -ErrorAction SilentlyContinue
       
        $elapsedTime = (Get-Date) - $startTime
        $elapsedMinutes = [int]$elapsedTime.TotalMinutes
        $elapsedSeconds = [int]($elapsedTime.TotalSeconds % 60)
       
        Write-Log "Full Scan completed - Drives: $totalDrives, Files: $totalFiles, Threats: $totalThreats, Time: ${elapsedMinutes}m ${elapsedSeconds}s" -Level "INFO"
        Write-ScanStatus -Scanning $false -FilesScanned $totalFiles -ThreatsFound $totalThreats -ProgressPercent 100 -ScanType "Full" -Message "Full scan completed"
       
        if ($totalThreats -gt 0) {
            Write-Log "Full Scan detected $totalThreats threat(s)! Check log for details." -Level "WARNING"
        }
       
        return $true
    }
    catch {
        Write-Log "Full Scan failed - $($_.Exception.Message)" -Level "ERROR"
        Remove-Item $PidFile -Force -ErrorAction SilentlyContinue
        Clear-ScanStatus
        return $false
    }
}

function Start-CustomScan {
    param([string]$Path)
   
    Write-Log "Custom Scan initiated for: $Path" -Level "INFO"
   
    # Force clear stale locks first
    Force-ClearScanLock
   
    if (-not (Test-Path $Path)) {
        Write-Log "Path does not exist: $Path - aborting" -Level "ERROR"
        return $false
    }
   
    if (Test-ScanRunning) {
        Write-Log "A scan is already in progress - aborting" -Level "ERROR"
        return $false
    }
   
    $startTime = Get-Date
    Write-Log "Checking path type..." -Level "DEBUG"
   
    $isDirectory = (Get-Item $Path).PSIsContainer
    if ($isDirectory) {
        Write-Log "Scanning directory: $Path" -Level "INFO"
    } else {
        Write-Log "Scanning file: $Path" -Level "INFO"
    }
   
    try {
        Write-ScanStatus -Scanning $true -CurrentFolder $Path -ScanType "Custom" -Message "Scanning custom path..."
       
        # Build scan arguments with verbose mode
        $scanArgs = "--database=`"$DatabaseDir`" --log=`"$ScanLog`" --verbose --recursive --infected `"$Path`""
       
        # Start the process and capture output
        $psi = New-Object System.Diagnostics.ProcessStartInfo
        $psi.FileName = $ClamScan
        $psi.Arguments = $scanArgs
        $psi.UseShellExecute = $false
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.CreateNoWindow = $true
       
        $process = New-Object System.Diagnostics.Process
        $process.StartInfo = $psi
        $process.Start() | Out-Null
       
        # Store PID for tracking
        $process.Id | Out-File -FilePath $PidFile -Force
       
        # Wait for completion and capture output
        $stdout = $process.StandardOutput.ReadToEnd()
        $stderr = $process.StandardError.ReadToEnd()
        $process.WaitForExit()
       
        # Clean up PID file
        Remove-Item $PidFile -Force -ErrorAction SilentlyContinue
       
        $elapsedTime = (Get-Date) - $startTime
        $elapsedSeconds = [int]$elapsedTime.TotalSeconds
       
        # Parse clamscan output for summary
        $totalThreats = 0
        $totalFiles = 0
        if ($stdout -match "Infected files:\s*(\d+)") {
            $totalThreats = [int]$Matches[1]
        }
        if ($stdout -match "Scanned files:\s*(\d+)") {
            $totalFiles = [int]$Matches[1]
        }
       
        # Log any FOUND items for Wazuh to detect
        $stdout -split "`n" | Where-Object { $_ -match "FOUND" } | ForEach-Object {
            Write-Log "$_" -Level "WARNING"
        }
       
        Write-Log "Custom Scan completed - Files: $totalFiles, Threats: $totalThreats, Time: ${elapsedSeconds}s" -Level "INFO"
       
        if ($totalThreats -gt 0) {
            Write-Log "Custom Scan completed - $totalThreats threats detected! Check log for details." -Level "WARNING"
            Write-ScanStatus -Scanning $false -FilesScanned $totalFiles -ThreatsFound $totalThreats -ProgressPercent 100 -ScanType "Custom" -Message "Threats detected!"
        } else {
            Write-Log "Custom Scan completed - No threats found" -Level "INFO"
            Write-ScanStatus -Scanning $false -FilesScanned $totalFiles -ThreatsFound 0 -ProgressPercent 100 -ScanType "Custom" -Message "Scan completed - no threats"
        }
       
        return $true
    }
    catch {
        Write-Log "Custom Scan failed - $($_.Exception.Message)" -Level "ERROR"
        Remove-Item $PidFile -Force -ErrorAction SilentlyContinue
        Clear-ScanStatus
        return $false
    }
}

function Stop-Scan {
    Write-Log "Stop scan request received" -Level "INFO"
   
    # Try to stop via PID file
    if (Test-Path $PidFile) {
        $scanPid = Get-Content $PidFile -ErrorAction SilentlyContinue
        if ($scanPid) {
            Write-Log "Stopping scan process with PID: $scanPid" -Level "DEBUG"
            Stop-Process -Id $scanPid -Force -ErrorAction SilentlyContinue
        }
        Remove-Item $PidFile -Force -ErrorAction SilentlyContinue
    }
   
    # Also kill any running clamscan processes
    $runningScans = Get-Process -Name "clamscan" -ErrorAction SilentlyContinue
    if ($runningScans) {
        Write-Log "Found $($runningScans.Count) running clamscan process(es) - terminating" -Level "INFO"
        $runningScans | Stop-Process -Force -ErrorAction SilentlyContinue
    }
   
    Clear-ScanStatus
    Write-Log "Scan stopped successfully" -Level "INFO"
    return $true
}

function Update-Database {
    Write-Log "Database update initiated" -Level "INFO"
    Write-Log "FreshClam path: $FreshClam" -Level "DEBUG"
    Write-Log "Database directory: $DatabaseDir" -Level "DEBUG"
   
    $startTime = Get-Date
   
    try {
        $updateArgs = @(
            "--config-file=$FreshConf",
            "--datadir=$DatabaseDir",
            "--log=$UpdateLog"
        )
       
        Write-Log "Starting FreshClam with arguments: $($updateArgs -join ' ')" -Level "DEBUG"
        $process = Start-Process -FilePath $FreshClam -ArgumentList $updateArgs -NoNewWindow -PassThru -Wait
       
        $elapsedTime = (Get-Date) - $startTime
        $elapsedSeconds = [int]$elapsedTime.TotalSeconds
       
        if ($process.ExitCode -eq 0) {
            Write-Log "Database updated successfully, Time: ${elapsedSeconds}s" -Level "INFO"
            return $true
        } elseif ($process.ExitCode -eq 1) {
            Write-Log "Database already up-to-date, Time: ${elapsedSeconds}s" -Level "INFO"
            return $true
        } else {
            Write-Log "Database update completed with code: $($process.ExitCode), Time: ${elapsedSeconds}s" -Level "WARNING"
            return $false
        }
    }
    catch {
        Write-Log "Database update failed - $($_.Exception.Message)" -Level "ERROR"
        return $false
    }
}

function Get-ScheduleConfig {
    Write-Log "Reading schedule configuration from: $ScheduleConfig" -Level "DEBUG"
   
    if (-not (Test-Path $ScheduleConfig)) {
        Write-Log "Schedule config file not found, creating default" -Level "INFO"
        $defaultConfig = @{
            enabled = $false
            scan_type = "quick"
            schedule_type = "daily"
            time = "02:00"
            days_of_week = @("Sunday")
            custom_paths = @()
            interval_hours = 24
            last_scan = $null
            next_scan = $null
        }
        $defaultConfig | ConvertTo-Json -Depth 3 | Set-Content -Path $ScheduleConfig -Force
        return $defaultConfig
    }
   
    try {
        $config = Get-Content -Path $ScheduleConfig -Raw | ConvertFrom-Json
        Write-Log "Schedule config loaded: enabled=$($config.enabled), type=$($config.scan_type), schedule=$($config.schedule_type)" -Level "DEBUG"
        return $config
    }
    catch {
        Write-Log "Failed to parse schedule config: $($_.Exception.Message)" -Level "ERROR"
        return $null
    }
}

function Set-ScheduleConfig {
    param(
        [bool]$Enabled = $false,
        [string]$ScanType = "quick",
        [string]$ScheduleType = "daily",
        [string]$Time = "02:00",
        [string[]]$DaysOfWeek = @("Sunday"),
        [string[]]$CustomPaths = @(),
        [int]$IntervalHours = 24
    )
   
    Write-Log "Saving schedule configuration" -Level "INFO"
    Write-Log "Config: enabled=$Enabled, scan_type=$ScanType, schedule_type=$ScheduleType, time=$Time, interval=$IntervalHours" -Level "DEBUG"
   
    try {
        $config = @{
            enabled = $Enabled
            scan_type = $ScanType
            schedule_type = $ScheduleType
            time = $Time
            days_of_week = $DaysOfWeek
            custom_paths = $CustomPaths
            interval_hours = $IntervalHours
            last_scan = $null
            next_scan = $null
        }
       
        $config | ConvertTo-Json -Depth 3 | Set-Content -Path $ScheduleConfig -Force
        Write-Log "Schedule configuration saved successfully" -Level "INFO"
        return $true
    }
    catch {
        Write-Log "Failed to save schedule config: $($_.Exception.Message)" -Level "ERROR"
        return $false
    }
}

function Set-Schedule {
    param(
        [string]$ScanType,
        [int]$IntervalHours
    )
   
    Write-Log "Configuring scheduled scan: $ScanType every $IntervalHours hours" -Level "INFO"
    Write-Log "Config file path: $ScheduleConfig" -Level "DEBUG"
   
    # Normalize scan type for config file (quick/full instead of quickscan/fullscan)
    $configScanType = $ScanType -replace "scan$", ""
   
    # Determine schedule type from interval
    $scheduleType = "interval"
    $time = "02:00"
    $daysOfWeek = @("Sunday")
   
    if ($IntervalHours -ge 168) {
        $scheduleType = "weekly"
        Write-Log "Schedule type: Weekly on Sunday at $time" -Level "DEBUG"
    } elseif ($IntervalHours -ge 24) {
        $scheduleType = "daily"
        Write-Log "Schedule type: Daily at $time" -Level "DEBUG"
    } else {
        $scheduleType = "interval"
        Write-Log "Schedule type: Every $IntervalHours hour(s)" -Level "DEBUG"
    }
   
    try {
        # Remove existing task if present
        Write-Log "Removing existing scheduled task if present..." -Level "DEBUG"
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
       
        # Create the action - use original ScanType for scheduled task
        $scriptPath = $MyInvocation.MyCommand.Path
        if (-not $scriptPath) {
            $scriptPath = Join-Path $ClamAVDir "ClamAVControl.ps1"
        }
        $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -NoProfile -File `"$scriptPath`" $ScanType"
        Write-Log "Task action: powershell.exe -File $scriptPath $ScanType" -Level "DEBUG"
       
        # Create the trigger based on interval
        if ($IntervalHours -ge 168) {
            $trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At $time
        } elseif ($IntervalHours -ge 24) {
            $trigger = New-ScheduledTaskTrigger -Daily -At $time
        } else {
            # For interval-based triggers, use a 49-day duration (max practical limit for Windows Task Scheduler)
            # Note: Cannot use [TimeSpan]::MaxValue as it creates invalid XML for Task Scheduler
            $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(5) -RepetitionInterval (New-TimeSpan -Hours $IntervalHours) -RepetitionDuration (New-TimeSpan -Days 49)
        }
       
        # Create principal (run as SYSTEM with highest privileges)
        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
       
        # Create settings
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
       
        # Register the task
        Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
       
        Write-Log "Scheduled task '$TaskName' created successfully" -Level "INFO"
       
        # Save to config file - use normalized scan type
        Set-ScheduleConfig -Enabled $true -ScanType $configScanType -ScheduleType $scheduleType -Time $time -DaysOfWeek $daysOfWeek -IntervalHours $IntervalHours
       
        return $true
    }
    catch {
        Write-Log "Failed to create scheduled task - $($_.Exception.Message)" -Level "ERROR"
        return $false
    }
}

function Remove-Schedule {
    Write-Log "Removing scheduled scan..." -Level "INFO"
   
    try {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
        Write-Log "Scheduled task '$TaskName' removed" -Level "INFO"
       
        # Update config file
        $config = Get-ScheduleConfig
        if ($config) {
            Set-ScheduleConfig -Enabled $false -ScanType $config.scan_type -ScheduleType $config.schedule_type -Time $config.time -IntervalHours $config.interval_hours
        }
       
        return $true
    }
    catch {
        Write-Log "Failed to remove scheduled task - $($_.Exception.Message)" -Level "ERROR"
        return $false
    }
}

function Get-Status {
    if (Test-ScanRunning) {
        Write-Output "SCANNING"
    } else {
        Write-Output "IDLE"
    }
}

# Main execution
switch ($Action.ToLower()) {
    "quickscan" {
        if (Start-QuickScan) {
            Write-Output "Quick scan completed successfully"
            exit 0
        } else {
            Write-Output "Quick scan failed"
            exit 1
        }
    }
    "fullscan" {
        if (Start-FullScan) {
            Write-Output "Full scan completed successfully"
            exit 0
        } else {
            Write-Output "Full scan failed"
            exit 1
        }
    }
    "customscan" {
        if (Start-CustomScan -Path $Param1) {
            Write-Output "Custom scan completed successfully"
            exit 0
        } else {
            Write-Output "Custom scan failed"
            exit 1
        }
    }
    "stop" {
        if (Stop-Scan) {
            Write-Output "Scan stopped"
            exit 0
        } else {
            Write-Output "Failed to stop scan"
            exit 1
        }
    }
    "update" {
        if (Update-Database) {
            Write-Output "Database updated successfully"
            exit 0
        } else {
            Write-Output "Database update failed"
            exit 1
        }
    }
    "schedule" {
        if (Set-Schedule -ScanType $Param1 -IntervalHours $Param2) {
            Write-Output "Schedule configured successfully"
            exit 0
        } else {
            Write-Output "Failed to configure schedule"
            exit 1
        }
    }
    "unschedule" {
        if (Remove-Schedule) {
            Write-Output "Schedule removed successfully"
            exit 0
        } else {
            Write-Output "Failed to remove schedule"
            exit 1
        }
    }
    "status" {
        Get-Status
        exit 0
    }
    default {
        Write-Output "ClamAV Control Script"
        Write-Output ""
        Write-Output "Usage: ClamAVControl.ps1 <action> [parameters]"
        Write-Output ""
        Write-Output "Actions:"
        Write-Output "  quickscan              - Scan common threat locations"
        Write-Output "  fullscan               - Scan all fixed drives"
        Write-Output "  customscan <path>      - Scan specified folder"
        Write-Output "  stop                   - Stop running scan"
        Write-Output "  update                 - Update virus database"
        Write-Output "  schedule <type> <hrs>  - Configure scheduled scan"
        Write-Output "  unschedule             - Remove scheduled scan"
        Write-Output "  status                 - Check scan status"
        exit 0
    }
}