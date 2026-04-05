#Requires -Version 7.0
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    RiskNoX Security Agent Control Script
    
.DESCRIPTION
    Control script for managing RiskNoX Security Agent backend service.
    All operations are handled by the backend_server.py API.
    
.PARAMETER Action
    The action to perform: start, stop, restart, status, help
    
.EXAMPLE
    .\RiskNoX-Control.ps1 -Action start
    Starts the RiskNoX Security Agent backend service
    
.EXAMPLE
    .\RiskNoX-Control.ps1 -Action status
    Show current status of the backend service
    
.NOTES
    Author: RiskNoX Security Team
    Version: 2.0.0
    Requires: PowerShell 7.0 or later, Administrator privileges
    Note: All security operations are performed through the backend API
#>

param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('start', 'stop', 'restart', 'status', 'help')]
    [string]$Action
)

# Configuration
$Script:Config = @{
    RootPath       = Split-Path -Parent $MyInvocation.MyCommand.Path
    BackendScript  = "backend_server.py"
    BackendPort    = 5000
    VirtualEnvPath = ".venv"
    LogsPath       = "logs"
}

# Logging functions
function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('INFO', 'WARN', 'ERROR', 'SUCCESS')]
        [string]$Level = 'INFO'
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $color = switch ($Level) {
        'INFO'    { 'White' }
        'WARN'    { 'Yellow' }
        'ERROR'   { 'Red' }
        'SUCCESS' { 'Green' }
    }
    
    Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $color
}

function Test-Dependencies {
    Write-Log "Checking dependencies..." -Level INFO
    
    # Check PowerShell version
    if ($PSVersionTable.PSVersion.Major -lt 7) {
        Write-Log "PowerShell 7.0 or later is required. Current version: $($PSVersionTable.PSVersion)" -Level ERROR
        return $false
    }
    
    # Check Python virtual environment
    $venvPath = Join-Path $Script:Config.RootPath $Script:Config.VirtualEnvPath
    if (-not (Test-Path $venvPath)) {
        Write-Log "Python virtual environment not found at: $venvPath" -Level ERROR
        Write-Log "Please run the installer first: .\RiskNoX-Agent-Installer.ps1 -Action install" -Level ERROR
        return $false
    }
    
    # Check backend script
    $backendPath = Join-Path $Script:Config.RootPath $Script:Config.BackendScript
    if (-not (Test-Path $backendPath)) {
        Write-Log "Backend script not found at: $backendPath" -Level ERROR
        return $false
    }
    
    Write-Log "All dependencies verified" -Level SUCCESS
    return $true
}

function Get-AllBackendProcesses {
    # Get all Python processes running backend_server.py
    $allPythonProcesses = Get-Process -Name "python" -ErrorAction SilentlyContinue
    $backendProcesses = @()
    
    if ($allPythonProcesses) {
        foreach ($proc in $allPythonProcesses) {
            try {
                $commandLine = (Get-WmiObject Win32_Process -Filter "ProcessId = $($proc.Id)").CommandLine
                if ($commandLine -and $commandLine -like "*backend_server.py*") {
                    $backendProcesses += $proc
                }
            }
            catch {
                # Continue if we can't get command line
            }
        }
    }
    
    # Also check for processes listening on the backend port
    try {
        $netstat = netstat -ano | Select-String ":$($Script:Config.BackendPort) "
        if ($netstat) {
            foreach ($line in $netstat) {
                $processId = ($line -split '\s+')[-1]
                $proc = Get-Process -Id $processId -ErrorAction SilentlyContinue
                if ($proc -and $proc.Id -notin $backendProcesses.Id) {
                    $backendProcesses += $proc
                }
            }
        }
    }
    catch {
        # Continue if netstat fails
    }
    
    return $backendProcesses
}

function Start-Backend {
    Write-Log "Starting RiskNoX Security Agent Backend..." -Level INFO
    
    # Check if already running
    $existingProcesses = Get-AllBackendProcesses
    if ($existingProcesses -and $existingProcesses.Count -gt 0) {
        $firstProcess = $existingProcesses[0]
        Write-Log "Backend is already running (PID: $($firstProcess.Id))" -Level WARN
        Write-Log "Web interface: http://localhost:$($Script:Config.BackendPort)" -Level INFO
        return
    }
    
    # Set up paths
    $venvPython = Join-Path $Script:Config.RootPath "$($Script:Config.VirtualEnvPath)\Scripts\python.exe"
    $backendScript = Join-Path $Script:Config.RootPath $Script:Config.BackendScript
    
    # Start the backend
    try {
        Push-Location $Script:Config.RootPath
        
        $logFile = Join-Path $Script:Config.LogsPath "backend_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
        $logDir = Split-Path $logFile -Parent
        if (-not (Test-Path $logDir)) {
            New-Item -ItemType Directory -Path $logDir -Force | Out-Null
        }
        
        $process = Start-Process -FilePath $venvPython `
            -ArgumentList $backendScript `
            -WindowStyle Hidden `
            -RedirectStandardOutput $logFile `
            -RedirectStandardError $logFile `
            -PassThru
        
        Write-Log "Backend process started (PID: $($process.Id))" -Level INFO
        Write-Log "Waiting for backend to initialize..." -Level INFO
        
        # Wait for Flask to initialize
        Start-Sleep -Seconds 3
        
        # Verify it's running
        $maxAttempts = 10
        $attempt = 1
        $isRunning = $false
        
        while ($attempt -le $maxAttempts -and -not $isRunning) {
            $runningProcesses = Get-AllBackendProcesses
            if ($runningProcesses -and $runningProcesses.Count -gt 0) {
                $isRunning = $true
            } else {
                Start-Sleep -Seconds 1
                $attempt++
            }
        }
        
        if ($isRunning) {
            Write-Log "Backend started successfully" -Level SUCCESS
            Write-Log "Web interface: http://localhost:$($Script:Config.BackendPort)" -Level SUCCESS
            Write-Log "Logs: $logFile" -Level INFO
        } else {
            Write-Log "Backend failed to start or timed out" -Level ERROR
            Write-Log "Check logs: $logFile" -Level ERROR
            if (Test-Path $logFile) {
                Write-Log "Last log entries:" -Level INFO
                Get-Content $logFile -Tail 10 | ForEach-Object { Write-Log $_ }
            }
        }
    }
    catch {
        Write-Log "Failed to start backend: $($_.Exception.Message)" -Level ERROR
    }
    finally {
        Pop-Location
    }
}

function Stop-Backend {
    Write-Log "Stopping RiskNoX Security Agent Backend..." -Level INFO
    
    $processes = Get-AllBackendProcesses
    if ($processes -and $processes.Count -gt 0) {
        foreach ($process in $processes) {
            try {
                Write-Log "Stopping backend process (PID: $($process.Id))" -Level INFO
                Stop-Process -Id $process.Id -Force
            }
            catch {
                Write-Log "Failed to stop process $($process.Id): $($_.Exception.Message)" -Level ERROR
            }
        }
        
        Start-Sleep -Seconds 1
        
        # Verify stopped
        $remaining = Get-AllBackendProcesses
        if ($remaining -and $remaining.Count -gt 0) {
            Write-Log "Warning: $($remaining.Count) backend process(es) still running" -Level WARN
        } else {
            Write-Log "Backend stopped successfully" -Level SUCCESS
        }
    } else {
        Write-Log "Backend is not running" -Level WARN
    }
}

function Get-ServiceStatus {
    Write-Log "RiskNoX Security Agent Status" -Level INFO
    Write-Log "=" * 50
    
    # Backend status
    $backendProcesses = Get-AllBackendProcesses
    if ($backendProcesses -and $backendProcesses.Count -gt 0) {
        Write-Log "Backend Service: RUNNING" -Level SUCCESS
        foreach ($proc in $backendProcesses) {
            $memMB = [math]::Round($proc.WorkingSet64 / 1MB, 2)
            Write-Log "  PID: $($proc.Id) | Memory: $memMB MB" -Level INFO
        }
        Write-Log "  Web Interface: http://localhost:$($Script:Config.BackendPort)" -Level INFO
    } else {
        Write-Log "Backend Service: STOPPED" -Level ERROR
    }
    
    Write-Log ""
    Write-Log "All operations are performed through the backend API" -Level INFO
    Write-Log "Access the web interface to manage:" -Level INFO
    Write-Log "  - Antivirus scanning" -Level INFO
    Write-Log "  - Web URL blocking" -Level INFO
    Write-Log "  - Application blocking" -Level INFO
    Write-Log "  - Patch management" -Level INFO
}

function Show-Help {
    Write-Host @"

RiskNoX Security Agent Control Script
=====================================

USAGE:
    .\RiskNoX-Control.ps1 -Action <action>

ACTIONS:
    start       Start the backend service
    stop        Stop the backend service
    restart     Restart the backend service
    status      Show service status
    help        Show this help message

EXAMPLES:
    .\RiskNoX-Control.ps1 -Action start
    .\RiskNoX-Control.ps1 -Action status
    .\RiskNoX-Control.ps1 -Action restart

WEB INTERFACE:
    http://localhost:5000
    
    All security operations are performed through the backend API:
    - Antivirus scanning (full system, quick scan, directory scan)
    - Web URL blocking/unblocking
    - Application blocking/unblocking
    - Patch management
    - Scheduled scans

NOTES:
    - Administrator privileges required
    - Requires PowerShell 7.0 or later
    - Run RiskNoX-Agent-Installer.ps1 first for initial setup

"@ -ForegroundColor Cyan
}

# Main execution
function Main {
    Write-Log "RiskNoX Security Agent Control Script v2.0.0" -Level INFO
    Write-Log "Action: $Action" -Level INFO
    Write-Log ""
    
    Set-Location $Script:Config.RootPath
    
    switch ($Action.ToLower()) {
        'start' {
            if (-not (Test-Dependencies)) { return }
            Start-Backend
        }
        
        'stop' {
            Stop-Backend
        }
        
        'restart' {
            if (-not (Test-Dependencies)) { return }
            Stop-Backend
            Start-Sleep -Seconds 2
            Start-Backend
        }
        
        'status' {
            Get-ServiceStatus
        }
        
        'help' {
            Show-Help
        }
        
        default {
            Write-Log "Unknown action: $Action" -Level ERROR
            Show-Help
        }
    }
}

if ($MyInvocation.InvocationName -ne '.') {
    Main
}