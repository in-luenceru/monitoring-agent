#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Install RiskNoX Supervisor as a Windows Service using NSSM
.DESCRIPTION
    Installs the supervisor.exe as a Windows service with automatic startup
#>

param(
    [string]$ServiceName = "RiskNoXSupervisor",
    [string]$DisplayName = "RiskNoX Security Supervisor",
    [string]$Description = "Manages RiskNoX security agents and monitoring services"
)

$ErrorActionPreference = "Stop"
$REPO_ROOT = Split-Path $PSScriptRoot -Parent
$DIST_DIR = Join-Path $REPO_ROOT "dist"
$SUPERVISOR_EXE = Join-Path $DIST_DIR "supervisor.exe"
$LOGS_DIR = Join-Path $REPO_ROOT "logs"
$NSSM_DIR = Join-Path $PSScriptRoot "nssm"
$NSSM_EXE = Join-Path $NSSM_DIR "win64\nssm.exe"

function Write-InstallLog {
    param([string]$Message, [string]$Level = "INFO")
    $colors = @{ INFO = "Cyan"; SUCCESS = "Green"; ERROR = "Red"; WARN = "Yellow" }
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $colors[$Level]
}

function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-Prerequisites {
    Write-InstallLog "Checking prerequisites..." "INFO"
    
    # Check admin rights
    if (-not (Test-Administrator)) {
        Write-InstallLog "This script requires Administrator privileges" "ERROR"
        return $false
    }
    
    # Check if NSSM exists
    if (-not (Test-Path $NSSM_EXE)) {
        Write-InstallLog "NSSM not found. Downloading..." "WARN"
        
        $downloadScript = Join-Path $PSScriptRoot "download_nssm.ps1"
        if (Test-Path $downloadScript) {
            & $downloadScript
            if ($LASTEXITCODE -ne 0) {
                Write-InstallLog "Failed to download NSSM" "ERROR"
                return $false
            }
        }
        else {
            Write-InstallLog "NSSM download script not found: $downloadScript" "ERROR"
            Write-InstallLog "Please download NSSM manually from https://nssm.cc/" "ERROR"
            return $false
        }
    }
    
    # Check if supervisor.exe exists
    if (-not (Test-Path $SUPERVISOR_EXE)) {
        Write-InstallLog "Supervisor executable not found: $SUPERVISOR_EXE" "ERROR"
        Write-InstallLog "Please run tools\build.ps1 first to build the supervisor" "ERROR"
        return $false
    }
    
    # Ensure logs directory exists
    if (-not (Test-Path $LOGS_DIR)) {
        New-Item -ItemType Directory -Path $LOGS_DIR -Force | Out-Null
    }
    
    Write-InstallLog "Prerequisites check passed" "SUCCESS"
    
    # Grant SYSTEM account full permissions to the repository directory
    Write-InstallLog "Granting SYSTEM account permissions..." "INFO"
    try {
        $icaclsResult = icacls $REPO_ROOT /grant "SYSTEM:(OI)(CI)F" /T /Q 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-InstallLog "SYSTEM permissions granted successfully" "SUCCESS"
        } else {
            Write-InstallLog "Warning: Failed to grant SYSTEM permissions (non-critical)" "WARN"
        }
    }
    catch {
        Write-InstallLog "Warning: Could not modify permissions: $_" "WARN"
    }
    
    return $true
}

function Remove-ExistingService {
    param([string]$Name)
    
    try {
        $service = Get-Service -Name $Name -ErrorAction SilentlyContinue
        if ($service) {
            Write-InstallLog "Found existing service: $Name" "WARN"
            Write-InstallLog "Stopping and removing existing service..." "INFO"
            
            # Stop service if running
            if ($service.Status -eq 'Running') {
                Stop-Service -Name $Name -Force
                Start-Sleep -Seconds 3
            }
            
            # Remove using NSSM
            & $NSSM_EXE remove $Name confirm
            
            Start-Sleep -Seconds 2
            Write-InstallLog "Existing service removed" "SUCCESS"
        }
    }
    catch {
        Write-InstallLog "Error removing existing service: $_" "WARN"
    }
}

function Install-SupervisorService {
    Write-InstallLog "Installing $ServiceName service..." "INFO"
    
    try {
        # Remove existing service if present
        Remove-ExistingService -Name $ServiceName
        
        # Install service with NSSM
        Write-InstallLog "Running: nssm install $ServiceName $SUPERVISOR_EXE" "INFO"
        & $NSSM_EXE install $ServiceName $SUPERVISOR_EXE
        
        if ($LASTEXITCODE -ne 0) {
            Write-InstallLog "NSSM install failed with exit code $LASTEXITCODE" "ERROR"
            return $false
        }
        
        Write-InstallLog "Service installed successfully" "SUCCESS"
        
        # Configure service
        Write-InstallLog "Configuring service parameters..." "INFO"
        
        # Set display name and description
        & $NSSM_EXE set $ServiceName DisplayName $DisplayName
        & $NSSM_EXE set $ServiceName Description $Description
        
        # Set working directory
        & $NSSM_EXE set $ServiceName AppDirectory $REPO_ROOT
        
        # Set startup type to automatic
        & $NSSM_EXE set $ServiceName Start SERVICE_AUTO_START
        
        # Set log files
        $stdoutLog = Join-Path $LOGS_DIR "supervisor_stdout.log"
        $stderrLog = Join-Path $LOGS_DIR "supervisor_stderr.log"
        
        & $NSSM_EXE set $ServiceName AppStdout $stdoutLog
        & $NSSM_EXE set $ServiceName AppStderr $stderrLog
        
        # Set log rotation (10 MB per file, keep 5 files)
        & $NSSM_EXE set $ServiceName AppStdoutCreationDisposition 4  # Append
        & $NSSM_EXE set $ServiceName AppStderrCreationDisposition 4  # Append
        & $NSSM_EXE set $ServiceName AppRotateFiles 1
        & $NSSM_EXE set $ServiceName AppRotateOnline 1
        & $NSSM_EXE set $ServiceName AppRotateSeconds 86400  # Daily
        & $NSSM_EXE set $ServiceName AppRotateBytes 10485760  # 10 MB
        
        # Set restart behavior
        & $NSSM_EXE set $ServiceName AppExit Default Restart
        & $NSSM_EXE set $ServiceName AppRestartDelay 5000  # 5 seconds
        
        # Set throttle (prevent rapid restart loops)
        & $NSSM_EXE set $ServiceName AppThrottle 10000  # 10 seconds
        
        # Set process priority to normal
        & $NSSM_EXE set $ServiceName AppPriority NORMAL_PRIORITY_CLASS
        
        # Set service to run as Local System
        & $NSSM_EXE set $ServiceName ObjectName LocalSystem
        
        Write-InstallLog "Service configuration completed" "SUCCESS"
        
        return $true
    }
    catch {
        Write-InstallLog "Failed to install service: $_" "ERROR"
        return $false
    }
}

function Start-SupervisorService {
    Write-InstallLog "Starting $ServiceName service..." "INFO"
    
    try {
        Start-Service -Name $ServiceName
        Start-Sleep -Seconds 3
        
        $service = Get-Service -Name $ServiceName
        if ($service.Status -eq 'Running') {
            Write-InstallLog "Service started successfully" "SUCCESS"
            return $true
        }
        else {
            Write-InstallLog "Service failed to start. Status: $($service.Status)" "ERROR"
            return $false
        }
    }
    catch {
        Write-InstallLog "Failed to start service: $_" "ERROR"
        return $false
    }
}

function Show-ServiceInfo {
    param([bool]$ProtectionApplied = $false)
    
    Write-InstallLog "" "INFO"
    Write-InstallLog "========================================" "INFO"
    Write-InstallLog "  Service Installation Complete!       " "SUCCESS"
    Write-InstallLog "========================================" "INFO"
    Write-InstallLog "" "INFO"
    Write-InstallLog "Service Name: $ServiceName" "INFO"
    Write-InstallLog "Display Name: $DisplayName" "INFO"
    Write-InstallLog "Executable: $SUPERVISOR_EXE" "INFO"
    Write-InstallLog "Working Dir: $REPO_ROOT" "INFO"
    Write-InstallLog "Startup: Automatic" "INFO"
    Write-InstallLog "Account: LocalSystem (highest privileges)" "INFO"
    
    if ($ProtectionApplied) {
        Write-InstallLog "" "INFO"
        Write-InstallLog "Protection Status: ENABLED" "SUCCESS"
        Write-InstallLog "  • Running as LocalSystem" "INFO"
        Write-InstallLog "  • SDDL protection active (admins cannot stop)" "INFO"
        Write-InstallLog "  • Auto-restart on failure enabled" "INFO"
    }
    
    Write-InstallLog "" "INFO"
    Write-InstallLog "Management Commands:" "INFO"
    Write-InstallLog "  Start:     .\tools\start.ps1" "INFO"
    if ($ProtectionApplied) {
        Write-InstallLog "  Stop:      (Requires SYSTEM privileges or remote control)" "WARN"
    }
    else {
        Write-InstallLog "  Stop:      .\tools\stop.ps1" "INFO"
    }
    Write-InstallLog "  Restart:   .\tools\restart.ps1" "INFO"
    Write-InstallLog "  Status:    .\tools\status.ps1" "INFO"
    Write-InstallLog "  Uninstall: .\tools\uninstall_service.ps1" "INFO"
    Write-InstallLog "" "INFO"
    Write-InstallLog "Protection Commands:" "INFO"
    Write-InstallLog "  Apply:     .\tools\protect_service.ps1" "INFO"
    Write-InstallLog "  Remove:    .\tools\unprotect_service.ps1" "INFO"
    Write-InstallLog "" "INFO"
    Write-InstallLog "Logs Directory: $LOGS_DIR" "INFO"
    Write-InstallLog "" "INFO"
    
    # Show current status
    try {
        $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($service) {
            Write-InstallLog "Current Status: $($service.Status)" "INFO"
        }
    }
    catch {}
}

function Set-ServiceProtection {
    Write-InstallLog "" "INFO"
    Write-InstallLog "Applying advanced service protection..." "INFO"
    
    try {
        # Apply LocalSystem account (already set, but verify)
        Write-InstallLog "Configuring LocalSystem privileges..." "INFO"
        
        # Apply SDDL protection to prevent admin stopping
        Write-InstallLog "Applying SDDL protection..." "INFO"
        $sddl = "D:(D;;WPDT;;;BA)(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)"
        
        $result = sc.exe sdset $ServiceName $sddl 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-InstallLog "Warning: Could not apply SDDL protection: $result" "WARN"
            return $false
        }
        
        # Apply failure recovery
        Write-InstallLog "Configuring auto-restart on failure..." "INFO"
        $result = sc.exe failure $ServiceName reset= 0 actions= restart/0/restart/0/restart/0 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-InstallLog "Warning: Could not configure auto-restart: $result" "WARN"
        }
        
        Write-InstallLog "Service protection applied successfully" "SUCCESS"
        Write-InstallLog "Administrators cannot stop this service (requires SYSTEM privileges)" "INFO"
        
        return $true
    }
    catch {
        Write-InstallLog "Warning: Failed to apply some protection measures: $_" "WARN"
        return $false
    }
}

function Main {
    Write-InstallLog "========================================" "INFO"
    Write-InstallLog "  RiskNoX Supervisor Service Installer " "INFO"
    Write-InstallLog "========================================" "INFO"
    
    # Check prerequisites
    if (-not (Test-Prerequisites)) {
        Write-InstallLog "Prerequisites check failed" "ERROR"
        exit 1
    }
    
    # Install service
    if (-not (Install-SupervisorService)) {
        Write-InstallLog "Service installation failed" "ERROR"
        exit 1
    }
    
    # Apply advanced service protection
    $protectionApplied = Set-ServiceProtection
    
    # Start service
    if (-not (Start-SupervisorService)) {
        Write-InstallLog "Service started with errors, check logs" "WARN"
    }
    
    # Show service info
    Show-ServiceInfo -ProtectionApplied $protectionApplied
    
    exit 0
}

# Run main
Main
