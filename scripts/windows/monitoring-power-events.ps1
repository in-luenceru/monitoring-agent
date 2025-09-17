# Monitoring Agent Windows Power Event Handler
# Comprehensive power management and event handling for Windows
# Copyright (C) 2025, Monitoring Solutions Inc.

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("Install", "Uninstall", "Test", "Monitor")]
    [string]$Action = "Install",
    
    [Parameter(Mandatory=$false)]
    [switch]$Verbose
)

# Import Windows PowerShell modules
Add-Type -AssemblyName System.ServiceProcess
Add-Type -AssemblyName System.Management

# Configuration
$script:AgentHome = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$script:LogFile = Join-Path $script:AgentHome "logs\monitoring-power-events.log"
$script:ControlScript = Join-Path $script:AgentHome "monitoring-agent-control.ps1"

# Ensure log directory exists
$logDir = Split-Path $script:LogFile -Parent
if (-not (Test-Path $logDir)) {
    New-Item -Path $logDir -ItemType Directory -Force | Out-Null
}

# Logging function
function Write-PowerLog {
    param(
        [string]$Level = "INFO",
        [string]$Message
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] [POWER] $Message"
    
    # Write to log file
    Add-Content -Path $script:LogFile -Value $logEntry -ErrorAction SilentlyContinue
    
    # Write to console if verbose
    if ($Verbose) {
        switch ($Level) {
            "ERROR" { Write-Host $logEntry -ForegroundColor Red }
            "WARN"  { Write-Host $logEntry -ForegroundColor Yellow }
            "INFO"  { Write-Host $logEntry -ForegroundColor Green }
            default { Write-Host $logEntry }
        }
    }
    
    # Write to Windows Event Log
    try {
        Write-EventLog -LogName Application -Source "MonitoringAgent" -EventId 1000 -EntryType Information -Message $logEntry -ErrorAction SilentlyContinue
    }
    catch {
        # Ignore errors writing to event log
    }
}

# Power event monitoring class
Add-Type @"
using System;
using System.Management;
using System.Diagnostics;

public class PowerEventMonitor
{
    private ManagementEventWatcher watcher;
    private string scriptPath;
    
    public PowerEventMonitor(string scriptPath)
    {
        this.scriptPath = scriptPath;
    }
    
    public void StartMonitoring()
    {
        try
        {
            // Monitor power events
            WqlEventQuery query = new WqlEventQuery("SELECT * FROM Win32_PowerManagementEvent");
            watcher = new ManagementEventWatcher(query);
            watcher.EventArrived += new EventArrivedEventHandler(PowerEventArrived);
            watcher.Start();
            
            // Also monitor system events
            WqlEventQuery sysQuery = new WqlEventQuery("SELECT * FROM Win32_SystemConfigurationChangeEvent");
            ManagementEventWatcher sysWatcher = new ManagementEventWatcher(sysQuery);
            sysWatcher.EventArrived += new EventArrivedEventHandler(SystemEventArrived);
            sysWatcher.Start();
        }
        catch (Exception ex)
        {
            EventLog.WriteEntry("MonitoringAgent", "Power monitoring error: " + ex.Message, EventLogEntryType.Error);
        }
    }
    
    public void StopMonitoring()
    {
        if (watcher != null)
        {
            watcher.Stop();
            watcher.Dispose();
        }
    }
    
    private void PowerEventArrived(object sender, EventArrivedEventArgs e)
    {
        try
        {
            foreach (PropertyData prop in e.NewEvent.Properties)
            {
                ProcessStartInfo psi = new ProcessStartInfo();
                psi.FileName = "powershell.exe";
                psi.Arguments = string.Format("-ExecutionPolicy Bypass -File \"{0}\" -Action Monitor -EventType PowerEvent -EventData \"{1}\"", scriptPath, prop.Value);
                psi.WindowStyle = ProcessWindowStyle.Hidden;
                Process.Start(psi);
            }
        }
        catch (Exception ex)
        {
            EventLog.WriteEntry("MonitoringAgent", "Power event processing error: " + ex.Message, EventLogEntryType.Error);
        }
    }
    
    private void SystemEventArrived(object sender, EventArrivedEventArgs e)
    {
        try
        {
            ProcessStartInfo psi = new ProcessStartInfo();
            psi.FileName = "powershell.exe";
            psi.Arguments = string.Format("-ExecutionPolicy Bypass -File \"{0}\" -Action Monitor -EventType SystemEvent", scriptPath);
            psi.WindowStyle = ProcessWindowStyle.Hidden;
            Process.Start(psi);
        }
        catch (Exception ex)
        {
            EventLog.WriteEntry("MonitoringAgent", "System event processing error: " + ex.Message, EventLogEntryType.Error);
        }
    }
}
"@

function Install-PowerEventHandling {
    <#
    .SYNOPSIS
    Installs comprehensive Windows power event handling
    #>
    
    Write-PowerLog "INFO" "Installing Windows power event handling"
    
    try {
        # Create scheduled tasks for power events
        $taskName = "MonitoringAgent-PowerEvents"
        
        # Remove existing task if it exists
        $existingTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        if ($existingTask) {
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
            Write-PowerLog "DEBUG" "Removed existing power event task"
        }
        
        # Create trigger for system startup (includes resume from hibernation)
        $startupTrigger = New-ScheduledTaskTrigger -AtStartup
        $startupTrigger.Delay = "PT1M"  # 1 minute delay
        
        # Create trigger for user logon (includes resume from sleep)
        $logonTrigger = New-ScheduledTaskTrigger -AtLogOn
        $logonTrigger.Delay = "PT30S"  # 30 second delay
        
        # Create action to run power event handler
        $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$PSCommandPath`" -Action Monitor"
        
        # Configure task settings
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 10) -RestartOnIdle
        $settings.DisallowHardTerminate = $false
        $settings.RestartCount = 3
        $settings.RestartInterval = (New-TimeSpan -Minutes 1)
        
        # Create principal (run as SYSTEM with highest privileges)
        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        
        # Register the task with multiple triggers
        Register-ScheduledTask -TaskName $taskName -Trigger @($startupTrigger, $logonTrigger) -Action $action -Settings $settings -Principal $principal -Description "Monitoring Agent Power Event Handler" | Out-Null
        
        Write-PowerLog "INFO" "Created scheduled task for power event handling: $taskName"
        
        # Create WMI event subscription for real-time power monitoring
        $wmiTaskName = "MonitoringAgent-WMIEvents"
        
        # Remove existing WMI task
        $existingWmiTask = Get-ScheduledTask -TaskName $wmiTaskName -ErrorAction SilentlyContinue
        if ($existingWmiTask) {
            Unregister-ScheduledTask -TaskName $wmiTaskName -Confirm:$false
        }
        
        # Create trigger for system startup to start WMI monitoring
        $wmiTrigger = New-ScheduledTaskTrigger -AtStartup
        $wmiTrigger.Delay = "PT2M"  # 2 minute delay to ensure system is ready
        
        # Create action to start WMI monitoring
        $wmiAction = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$PSCommandPath`" -Action Monitor -Verbose"
        
        # Configure WMI task settings for continuous monitoring
        $wmiSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
        $wmiSettings.DisallowHardTerminate = $false
        $wmiSettings.ExecutionTimeLimit = "PT0S"  # No time limit
        
        # Create principal for WMI task
        $wmiPrincipal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        
        # Register WMI monitoring task
        Register-ScheduledTask -TaskName $wmiTaskName -Trigger $wmiTrigger -Action $wmiAction -Settings $wmiSettings -Principal $wmiPrincipal -Description "Monitoring Agent WMI Power Event Monitor" | Out-Null
        
        Write-PowerLog "INFO" "Created WMI monitoring task: $wmiTaskName"
        
        # Create registry entries for session notifications
        $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Startup\0"
        if (-not (Test-Path $regPath)) {
            New-Item -Path $regPath -Force | Out-Null
        }
        
        Set-ItemProperty -Path $regPath -Name "Script" -Value $PSCommandPath -Force
        Set-ItemProperty -Path $regPath -Name "Parameters" -Value "-Action Monitor -EventType SessionStart" -Force
        
        # Create event log source if it doesn't exist
        try {
            if (-not [System.Diagnostics.EventLog]::SourceExists("MonitoringAgentPower")) {
                [System.Diagnostics.EventLog]::CreateEventSource("MonitoringAgentPower", "Application")
                Write-PowerLog "INFO" "Created event log source: MonitoringAgentPower"
            }
        }
        catch {
            Write-PowerLog "WARN" "Could not create event log source: $($_.Exception.Message)"
        }
        
        # Test the installation
        if (Test-PowerEventInstallation) {
            Write-PowerLog "INFO" "✅ Power event handling installed successfully"
            return $true
        }
        else {
            Write-PowerLog "ERROR" "❌ Power event handling installation verification failed"
            return $false
        }
    }
    catch {
        Write-PowerLog "ERROR" "Failed to install power event handling: $($_.Exception.Message)"
        return $false
    }
}

function Uninstall-PowerEventHandling {
    <#
    .SYNOPSIS
    Removes Windows power event handling
    #>
    
    Write-PowerLog "INFO" "Uninstalling Windows power event handling"
    
    try {
        # Remove scheduled tasks
        $tasks = @("MonitoringAgent-PowerEvents", "MonitoringAgent-WMIEvents")
        
        foreach ($taskName in $tasks) {
            $task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
            if ($task) {
                Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
                Write-PowerLog "INFO" "Removed scheduled task: $taskName"
            }
        }
        
        # Remove registry entries
        $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Startup\0"
        if (Test-Path $regPath) {
            Remove-Item -Path $regPath -Recurse -Force -ErrorAction SilentlyContinue
        }
        
        Write-PowerLog "INFO" "✅ Power event handling uninstalled successfully"
        return $true
    }
    catch {
        Write-PowerLog "ERROR" "Failed to uninstall power event handling: $($_.Exception.Message)"
        return $false
    }
}

function Test-PowerEventInstallation {
    <#
    .SYNOPSIS
    Verifies power event handling installation
    #>
    
    $errors = 0
    
    # Check scheduled tasks
    $requiredTasks = @("MonitoringAgent-PowerEvents", "MonitoringAgent-WMIEvents")
    
    foreach ($taskName in $requiredTasks) {
        $task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        if ($task) {
            Write-PowerLog "INFO" "✓ Scheduled task exists: $taskName"
            
            if ($task.State -eq "Ready") {
                Write-PowerLog "INFO" "✓ Task is ready: $taskName"
            }
            else {
                Write-PowerLog "WARN" "⚠ Task not ready: $taskName (State: $($task.State))"
            }
        }
        else {
            Write-PowerLog "ERROR" "✗ Scheduled task missing: $taskName"
            $errors++
        }
    }
    
    # Check control script exists
    if (Test-Path $script:ControlScript) {
        Write-PowerLog "INFO" "✓ Control script found: $script:ControlScript"
    }
    else {
        Write-PowerLog "ERROR" "✗ Control script not found: $script:ControlScript"
        $errors++
    }
    
    return ($errors -eq 0)
}

function Start-PowerEventMonitoring {
    <#
    .SYNOPSIS
    Starts continuous power event monitoring
    #>
    
    Write-PowerLog "INFO" "Starting Windows power event monitoring"
    
    try {
        # Create and start the power event monitor
        $monitor = New-Object PowerEventMonitor($PSCommandPath)
        $monitor.StartMonitoring()
        
        Write-PowerLog "INFO" "Power event monitoring started successfully"
        
        # Keep the script running
        $global:PowerMonitorRunning = $true
        
        # Register for session events using .NET events
        Register-EngineEvent -SourceIdentifier "PowerShell.Exiting" -Action {
            Write-PowerLog "INFO" "Power event monitoring stopping"
            $global:PowerMonitorRunning = $false
        }
        
        # Main monitoring loop
        while ($global:PowerMonitorRunning) {
            Start-Sleep -Seconds 30
            
            # Periodic health check
            if ((Get-Date).Minute % 15 -eq 0) {
                Write-PowerLog "DEBUG" "Power monitor heartbeat"
                
                # Quick agent health check
                $agentService = Get-Service -Name "MonitoringAgent" -ErrorAction SilentlyContinue
                if ($agentService -and $agentService.Status -ne 'Running') {
                    Write-PowerLog "WARN" "Monitoring agent service not running - attempting restart"
                    
                    try {
                        Start-Service -Name "MonitoringAgent"
                        Write-PowerLog "INFO" "Successfully restarted monitoring agent service"
                    }
                    catch {
                        Write-PowerLog "ERROR" "Failed to restart monitoring agent service: $($_.Exception.Message)"
                    }
                }
            }
        }
        
        Write-PowerLog "INFO" "Power event monitoring stopped"
    }
    catch {
        Write-PowerLog "ERROR" "Error in power event monitoring: $($_.Exception.Message)"
    }
    finally {
        if ($monitor) {
            $monitor.StopMonitoring()
        }
    }
}

function Handle-PowerEvent {
    param(
        [string]$EventType,
        [string]$EventData
    )
    
    Write-PowerLog "INFO" "Handling power event: $EventType"
    
    switch ($EventType) {
        "PowerEvent" {
            Write-PowerLog "INFO" "Power state change detected: $EventData"
            
            # Wait for system to stabilize
            Start-Sleep -Seconds 10
            
            # Check monitoring agent health
            & $script:ControlScript health-check
            if ($LASTEXITCODE -ne 0) {
                Write-PowerLog "WARN" "Agent health check failed after power event - attempting restart"
                & $script:ControlScript restart
            }
        }
        "SystemEvent" {
            Write-PowerLog "INFO" "System configuration change detected"
            
            # Perform health check after system changes
            Start-Sleep -Seconds 5
            & $script:ControlScript health-check
        }
        "SessionStart" {
            Write-PowerLog "INFO" "User session started"
            
            # Check if agent is running after session start
            $agentService = Get-Service -Name "MonitoringAgent" -ErrorAction SilentlyContinue
            if ($agentService -and $agentService.Status -ne 'Running') {
                Write-PowerLog "WARN" "Agent not running at session start - starting service"
                Start-Service -Name "MonitoringAgent" -ErrorAction SilentlyContinue
            }
        }
    }
}

# Main execution logic
switch ($Action) {
    "Install" {
        Write-Host "Installing Windows Power Event Handling for Monitoring Agent..."
        if (Install-PowerEventHandling) {
            Write-Host "✅ Installation completed successfully!" -ForegroundColor Green
            Write-Host ""
            Write-Host "Windows power event features installed:" -ForegroundColor Cyan
            Write-Host "  ✓ Scheduled tasks for startup/logon events"
            Write-Host "  ✓ WMI event monitoring for real-time power events"
            Write-Host "  ✓ Automatic agent health checks after power events"
            Write-Host "  ✓ Service restart on power event failures"
            Write-Host ""
            Write-Host "Test the installation with:" -ForegroundColor Yellow
            Write-Host "  powershell -ExecutionPolicy Bypass -File '$PSCommandPath' -Action Test"
        }
        else {
            Write-Host "❌ Installation failed - check the log file: $script:LogFile" -ForegroundColor Red
            exit 1
        }
    }
    
    "Uninstall" {
        Write-Host "Uninstalling Windows Power Event Handling..."
        if (Uninstall-PowerEventHandling) {
            Write-Host "✅ Uninstallation completed successfully!" -ForegroundColor Green
        }
        else {
            Write-Host "❌ Uninstallation failed - check the log file: $script:LogFile" -ForegroundColor Red
            exit 1
        }
    }
    
    "Test" {
        Write-Host "Testing Windows Power Event Handling installation..."
        if (Test-PowerEventInstallation) {
            Write-Host "✅ Installation verification passed!" -ForegroundColor Green
        }
        else {
            Write-Host "❌ Installation verification failed!" -ForegroundColor Red
            exit 1
        }
    }
    
    "Monitor" {
        if ($args -contains "-EventType") {
            $eventTypeIndex = [array]::IndexOf($args, "-EventType")
            $eventType = $args[$eventTypeIndex + 1]
            $eventDataIndex = [array]::IndexOf($args, "-EventData")
            $eventData = if ($eventDataIndex -ge 0) { $args[$eventDataIndex + 1] } else { "" }
            
            Handle-PowerEvent -EventType $eventType -EventData $eventData
        }
        else {
            Start-PowerEventMonitoring
        }
    }
}

exit 0