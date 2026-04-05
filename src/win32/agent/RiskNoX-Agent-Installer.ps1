#Requires -RunAsAdministrator
<#
.SYNOPSIS
    RiskNoX Security Agent - Auto-Start Installer & Manager
.DESCRIPTION
    One-click installer with automatic background service startup
.PARAMETER Action
    install, start, stop, restart, status, uninstall, configure
#>

param(
    [ValidateSet('install', 'start', 'stop', 'restart', 'status', 'uninstall', 'configure')]
    [string]$Action = 'install'
)

$ErrorActionPreference = "Stop"
$AGENT_ROOT = $PSScriptRoot

function Write-Status {
    param([string]$Message, [string]$Type = "INFO")
    $colors = @{ INFO = "Cyan"; SUCCESS = "Green"; ERROR = "Red"; WARN = "Yellow" }
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[$timestamp] [$Type] $Message" -ForegroundColor $colors[$Type]
}

function Test-Python {
    try {
        $pythonVersion = python --version 2>&1
        if ($pythonVersion -match "Python 3\.(8|9|10|11|12)") {
            Write-Status "Python found: $pythonVersion" "SUCCESS"
            return $true
        }
    } catch {}
    
    Write-Status "Python 3.8+ required but not found" "ERROR"
    Write-Status "Download: https://www.python.org/downloads/" "INFO"
    return $false
}

function Install-Agent {
    Write-Status "========================================" "INFO"
    Write-Status "RiskNoX Security Agent Installer" "INFO"
    Write-Status "========================================" "INFO"
    
    # 1. Check Python
    if (-not (Test-Python)) { 
        Write-Status "Install Python 3.8+ and rerun" "ERROR"
        exit 1 
    }
    
    # 2. Create virtual environment
    Write-Status "Creating Python virtual environment..." "INFO"
    $venvPath = Join-Path $AGENT_ROOT ".venv"
    if (Test-Path $venvPath) {
        Write-Status "Virtual environment exists, skipping" "WARN"
    } else {
        python -m venv $venvPath
        Write-Status "Virtual environment created" "SUCCESS"
    }
    
    # 3. Install dependencies
    Write-Status "Installing Python packages..." "INFO"
    & "$venvPath\Scripts\python.exe" -m pip install --upgrade pip --quiet
    
    $requirementsFile = Join-Path $AGENT_ROOT "requirements.txt"
    if (Test-Path $requirementsFile) {
        Write-Status "Found requirements.txt, installing from file..." "INFO"
        & "$venvPath\Scripts\pip.exe" install -r $requirementsFile --quiet
    } else {
        Write-Status "requirements.txt not found, installing default packages..." "WARN"
        & "$venvPath\Scripts\pip.exe" install flask flask-cors psutil schedule requests pywin32 --quiet
    }
    
    Write-Status "Dependencies installed" "SUCCESS"
    
    # 4. Create directories
    Write-Status "Creating directory structure..." "INFO"
    $dirs = @("config", "logs", "web", "vendor", "vendor\database")
    foreach ($dir in $dirs) {
        $path = Join-Path $AGENT_ROOT $dir
        if (-not (Test-Path $path)) {
            New-Item -ItemType Directory -Path $path -Force | Out-Null
        }
    }
    Write-Status "Directories created" "SUCCESS"
    
    # 5. Verify required files
    Write-Status "Verifying required files..." "INFO"
    $requiredFiles = @("backend_server.py", "agent_poll.py", "RiskNoX-Control.ps1")
    $missing = @()
    foreach ($file in $requiredFiles) {
        if (-not (Test-Path (Join-Path $AGENT_ROOT $file))) {
            $missing += $file
        } else {
            Write-Status "Found: $file" "SUCCESS"
        }
    }
    
    if ($missing.Count -gt 0) {
        Write-Status "Missing files:" "ERROR"
        $missing | ForEach-Object { Write-Status "  - $_" "ERROR" }
        Write-Status "Ensure all files are in: $AGENT_ROOT" "ERROR"
        exit 1
    }
    Write-Status "All required files present and loaded" "SUCCESS"
    
    # 6. Configuration
    Write-Status "Creating configuration..." "INFO"
    $configFile = Join-Path $AGENT_ROOT "config\settings.json"
    $configDir = Split-Path $configFile -Parent
    if (-not (Test-Path $configDir)) {
        New-Item -ItemType Directory -Path $configDir -Force | Out-Null
    }
    
    $config = @{
        manager_url = "http://localhost:5001"
        agent_api_key = "agent-secure-key-xyz123"
        backend_port = 5000
        poll_interval = 30
    } | ConvertTo-Json
    $config | Set-Content $configFile
    Write-Status "Configuration saved to: $configFile" "SUCCESS"
    
    # 7. Create auto-start helper scripts
    Write-Status "Creating background service scripts..." "INFO"
    Create-BackgroundScripts
    
    Write-Status "========================================" "SUCCESS"
    Write-Status "Installation Complete!" "SUCCESS"
    Write-Status "========================================" "SUCCESS"
    Write-Status ""
    Write-Status "NEXT STEPS:" "INFO"
    Write-Status "1. Configure (if using Railway):" "INFO"
    Write-Status "   .\RiskNoX-Agent-Installer.ps1 -Action configure" "INFO"
    Write-Status "2. Start all services:" "INFO"
    Write-Status "   .\RiskNoX-Agent-Installer.ps1 -Action start" "INFO"
    Write-Status "3. Check status:" "INFO"
    Write-Status "   .\RiskNoX-Agent-Installer.ps1 -Action status" "INFO"
    Write-Status ""
    Write-Status "Web Interface: http://localhost:5000" "INFO"
}

function Create-BackgroundScripts {
    # Create backend starter script
    $backendScript = @'
$AGENT_ROOT = Split-Path -Parent $MyInvocation.MyCommand.Path
$venvPython = Join-Path $AGENT_ROOT ".venv\Scripts\python.exe"
$backendScript = Join-Path $AGENT_ROOT "backend_server.py"
$logFile = Join-Path $AGENT_ROOT "logs\backend.log"

Start-Process -FilePath $venvPython `
    -ArgumentList $backendScript `
    -WindowStyle Hidden `
    -RedirectStandardOutput $logFile `
    -RedirectStandardError $logFile
'@
    $backendScript | Set-Content (Join-Path $AGENT_ROOT "start_backend.ps1")
    
    # Create agent starter script
    $agentScript = @'
$AGENT_ROOT = Split-Path -Parent $MyInvocation.MyCommand.Path
$venvPython = Join-Path $AGENT_ROOT ".venv\Scripts\python.exe"
$agentScript = Join-Path $AGENT_ROOT "agent_poll.py"
$logFile = Join-Path $AGENT_ROOT "logs\agent.log"

Start-Process -FilePath $venvPython `
    -ArgumentList $agentScript `
    -WindowStyle Hidden `
    -RedirectStandardOutput $logFile `
    -RedirectStandardError $logFile
'@
    $agentScript | Set-Content (Join-Path $AGENT_ROOT "start_agent.ps1")
    
    Write-Status "Background service scripts created" "SUCCESS"
}

function Start-AllServices {
    Write-Status "Starting RiskNoX Security Agent..." "INFO"
    
    # Check if services are already running
    $backendProcs = @(Get-Process python -ErrorAction SilentlyContinue | 
        Where-Object { $_.CommandLine -like "*backend_server.py*" })
    $agentProcs = @(Get-Process python -ErrorAction SilentlyContinue | 
        Where-Object { $_.CommandLine -like "*agent_poll.py*" })
    
    if ($backendProcs.Count -gt 0 -or $agentProcs.Count -gt 0) {
        Write-Status "Services already running! Stopping them first..." "WARN"
        Stop-ExistingProcesses
        Start-Sleep -Seconds 2
    }
    
    # Start backend server
    Write-Status "Starting backend server (background)..." "INFO"
    $venvPython = Join-Path $AGENT_ROOT ".venv\Scripts\python.exe"
    $backendScript = Join-Path $AGENT_ROOT "backend_server.py"
    
    $backendJob = Start-Process -FilePath $venvPython `
        -ArgumentList $backendScript `
        -WindowStyle Hidden `
        -PassThru
    
    Write-Status "Backend started (PID: $($backendJob.Id))" "SUCCESS"
    Start-Sleep -Seconds 3
    
    # Verify backend started successfully
    $backendCheck = Get-Process -Id $backendJob.Id -ErrorAction SilentlyContinue
    if (-not $backendCheck) {
        Write-Status "Backend failed to start!" "ERROR"
        Write-Status "Try running manually: $venvPython $backendScript" "INFO"
        return
    }
    
    # Start agent polling service
    Write-Status "Starting agent polling service (background)..." "INFO"
    $agentScript = Join-Path $AGENT_ROOT "agent_poll.py"
    
    $agentJob = Start-Process -FilePath $venvPython `
        -ArgumentList $agentScript `
        -WindowStyle Hidden `
        -PassThru
    
    Write-Status "Agent service started (PID: $($agentJob.Id))" "SUCCESS"
    Start-Sleep -Seconds 2
    
    # Verify agent started successfully
    $agentCheck = Get-Process -Id $agentJob.Id -ErrorAction SilentlyContinue
    if (-not $agentCheck) {
        Write-Status "Agent failed to start!" "ERROR"
        Write-Status "Try running manually: $venvPython $agentScript" "INFO"
        return
    }
    
    Write-Status ""
    Write-Status "========================================" "SUCCESS"
    Write-Status "All services running in background!" "SUCCESS"
    Write-Status "========================================" "SUCCESS"
    Write-Status "Backend: http://localhost:5000" "INFO"
    Write-Status "Logs: $AGENT_ROOT\logs\" "INFO"
    Write-Status ""
    Write-Status "Check status: .\RiskNoX-Agent-Installer.ps1 -Action status" "INFO"
    Write-Status "View logs: Get-Content logs\backend.log -Tail 20 -Wait" "INFO"
}

function Stop-ExistingProcesses {
    param([switch]$Silent)
    
    # Stop backend
    $backendProcs = Get-Process python -ErrorAction SilentlyContinue | 
        Where-Object { $_.CommandLine -like "*backend_server.py*" }
    
    if ($backendProcs) {
        $backendProcs | Stop-Process -Force
        if (-not $Silent) {
            Write-Status "Stopped backend server" "SUCCESS"
        }
    }
    
    # Stop agent
    $agentProcs = Get-Process python -ErrorAction SilentlyContinue | 
        Where-Object { $_.CommandLine -like "*agent_poll.py*" }
    
    if ($agentProcs) {
        $agentProcs | Stop-Process -Force
        if (-not $Silent) {
            Write-Status "Stopped agent service" "SUCCESS"
        }
    }
}

function Stop-AllServices {
    Write-Status "Stopping RiskNoX Security Agent..." "INFO"
    Stop-ExistingProcesses
    Write-Status "All services stopped" "SUCCESS"
}

function Get-ServicesStatus {
    Write-Status "========================================" "INFO"
    Write-Status "RiskNoX Agent Status" "INFO"
    Write-Status "========================================" "INFO"
    
    # Check backend
    $backendProcs = @(Get-Process python -ErrorAction SilentlyContinue | 
        Where-Object { $_.CommandLine -like "*backend_server.py*" })
    
    if ($backendProcs.Count -gt 0) {
        if ($backendProcs.Count -eq 1) {
            $proc = $backendProcs[0]
            Write-Status "Backend Server: RUNNING (PID: $($proc.Id))" "SUCCESS"
            $memMB = [math]::Round($proc.WorkingSet64 / 1MB, 2)
            Write-Status "  Memory: $memMB MB" "INFO"
        } else {
            Write-Status "Backend Server: RUNNING ($($backendProcs.Count) instances)" "WARN"
            foreach ($proc in $backendProcs) {
                $memMB = [math]::Round($proc.WorkingSet64 / 1MB, 2)
                Write-Status "  PID: $($proc.Id) | Memory: $memMB MB" "INFO"
            }
        }
    } else {
        Write-Status "Backend Server: STOPPED" "ERROR"
    }
    
    # Check agent
    $agentProcs = @(Get-Process python -ErrorAction SilentlyContinue | 
        Where-Object { $_.CommandLine -like "*agent_poll.py*" })
    
    if ($agentProcs.Count -gt 0) {
        if ($agentProcs.Count -eq 1) {
            $proc = $agentProcs[0]
            Write-Status "Agent Service: RUNNING (PID: $($proc.Id))" "SUCCESS"
            $memMB = [math]::Round($proc.WorkingSet64 / 1MB, 2)
            Write-Status "  Memory: $memMB MB" "INFO"
        } else {
            Write-Status "Agent Service: RUNNING ($($agentProcs.Count) instances)" "WARN"
            foreach ($proc in $agentProcs) {
                $memMB = [math]::Round($proc.WorkingSet64 / 1MB, 2)
                Write-Status "  PID: $($proc.Id) | Memory: $memMB MB" "INFO"
            }
        }
    } else {
        Write-Status "Agent Service: STOPPED" "ERROR"
    }
    
    Write-Status ""
    
    # Test connectivity
    try {
        $response = Invoke-WebRequest -Uri "http://localhost:5000/" -TimeoutSec 2 -UseBasicParsing
        Write-Status "Backend API: ACCESSIBLE" "SUCCESS"
    } catch {
        Write-Status "Backend API: NOT ACCESSIBLE" "ERROR"
    }
    
    Write-Status ""
    Write-Status "Logs Location: $AGENT_ROOT\logs\" "INFO"
    Write-Status "View backend log: Get-Content logs\backend.log -Tail 20" "INFO"
    Write-Status "View agent log: Get-Content logs\agent.log -Tail 20" "INFO"
}

function Set-Configuration {
    $configFile = Join-Path $AGENT_ROOT "config\settings.json"
    $configDir = Split-Path $configFile -Parent
    
    if (-not (Test-Path $configDir)) {
        New-Item -ItemType Directory -Path $configDir -Force | Out-Null
    }
    
    Write-Status "========================================" "INFO"
    Write-Status "RiskNoX Agent Configuration" "INFO"
    Write-Status "========================================" "INFO"
    
    $managerUrl = Read-Host "Enter Manager URL (e.g., https://your-app.railway.app)"
    $apiKey = Read-Host "Enter Agent API Key"
    
    $config = @{
        manager_url = $managerUrl
        agent_api_key = $apiKey
        backend_port = 5000
        poll_interval = 30
    } | ConvertTo-Json
    
    $config | Set-Content $configFile
    
    # Update agent_poll.py
    $agentScript = Join-Path $AGENT_ROOT "agent_poll.py"
    if (Test-Path $agentScript) {
        $content = Get-Content $agentScript -Raw
        $content = $content -replace 'MANAGER_URL = ".*"', "MANAGER_URL = `"$managerUrl`""
        $content = $content -replace 'AGENT_API_KEY = ".*"', "AGENT_API_KEY = `"$apiKey`""
        $content | Set-Content $agentScript
    }
    
    Write-Status ""
    Write-Status "Configuration updated!" "SUCCESS"
    Write-Status "Restart services: .\RiskNoX-Agent-Installer.ps1 -Action restart" "INFO"
}

function Uninstall-Agent {
    Write-Status "Uninstalling RiskNoX Security Agent..." "WARN"
    
    Stop-AllServices
    
    Write-Status "Removing virtual environment..." "INFO"
    $venvPath = Join-Path $AGENT_ROOT ".venv"
    if (Test-Path $venvPath) {
        Remove-Item $venvPath -Recurse -Force
    }
    
    Write-Status "Uninstall complete" "SUCCESS"
    Write-Status "To fully remove, delete folder: $AGENT_ROOT" "INFO"
}

# Main execution
switch ($Action) {
    'install' { Install-Agent }
    'start' { Start-AllServices }
    'stop' { Stop-AllServices }
    'restart' { 
        Stop-AllServices
        Start-Sleep -Seconds 2
        Start-AllServices
    }
    'status' { Get-ServicesStatus }
    'configure' { Set-Configuration }
    'uninstall' { Uninstall-Agent }
}