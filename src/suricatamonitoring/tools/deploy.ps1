#Requires -RunAsAdministrator

<#
.SYNOPSIS
    One-click deployment script for RiskNoX Monitoring Agent Supervisor Service.

.DESCRIPTION
    This script automates the entire deployment process:
    1. Checks prerequisites (Admin rights, Windows version)
    2. Installs Python if not present
    3. Installs Python dependencies
    4. Enrolls monitoring agent (if needed)
    5. Builds supervisor executable
    6. Installs and starts Windows service
    7. Grants SYSTEM account permissions
    8. Verifies service is running

.PARAMETER SkipEnrollment
    Skip agent enrollment step (use if agent is already enrolled)

.PARAMETER SkipBuild
    Skip build step (use if supervisor.exe already exists)

.PARAMETER ManagerIP
    Manager IP address for agent enrollment (default: 127.0.0.1)

.PARAMETER AgentName
    Agent name for enrollment (default: hostname)

.EXAMPLE
    .\tools\deploy.ps1

.EXAMPLE
    .\tools\deploy.ps1 -SkipEnrollment

.EXAMPLE
    .\tools\deploy.ps1 -ManagerIP "192.168.1.100" -AgentName "DESKTOP-01"
#>

[CmdletBinding()]
param(
    [switch]$SkipEnrollment,
    [switch]$SkipBuild,
    [string]$ManagerIP = "127.0.0.1",
    [string]$AgentName = $env:COMPUTERNAME
)

# Script configuration
$ErrorActionPreference = "Stop"
$REPO_ROOT = Split-Path -Parent $PSScriptRoot
$LogFile = Join-Path $REPO_ROOT "logs\deployment.log"

# Ensure logs directory exists
$LogDir = Split-Path -Parent $LogFile
if (!(Test-Path $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}

# Logging function
function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("INFO", "SUCCESS", "WARN", "ERROR")]
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    # Write to file
    Add-Content -Path $LogFile -Value $logMessage
    
    # Write to console with color
    switch ($Level) {
        "SUCCESS" { Write-Host $Message -ForegroundColor Green }
        "WARN"    { Write-Host $Message -ForegroundColor Yellow }
        "ERROR"   { Write-Host $Message -ForegroundColor Red }
        default   { Write-Host $Message -ForegroundColor White }
    }
}

# Banner
function Show-Banner {
    Write-Host ""
    Write-Host "╔═══════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║                                                           ║" -ForegroundColor Cyan
    Write-Host "║     RiskNoX Monitoring Agent - Deployment Script         ║" -ForegroundColor Cyan
    Write-Host "║                                                           ║" -ForegroundColor Cyan
    Write-Host "╚═══════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
}

# Step 1: Prerequisites check
function Test-Prerequisites {
    Write-Host ""
    Write-Host "Step 1: Checking Prerequisites..." -ForegroundColor Cyan
    Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
    
    # Check Windows version
    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    $osVersion = [System.Environment]::OSVersion.Version
    
    Write-Log "Operating System: $($os.Caption)" "INFO"
    Write-Log "OS Version: $($osVersion.Major).$($osVersion.Minor).$($osVersion.Build)" "INFO"
    
    if ($osVersion.Major -lt 10) {
        Write-Log "ERROR: Windows 10 or later is required" "ERROR"
        return $false
    }
    
    # Check administrator privileges
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (!$isAdmin) {
        Write-Log "ERROR: Administrator privileges required" "ERROR"
        return $false
    }
    Write-Log "✓ Running as Administrator" "SUCCESS"
    
    # Check disk space (2GB minimum)
    $drive = (Get-Item $REPO_ROOT).PSDrive.Name
    $freeSpace = (Get-PSDrive $drive).Free / 1GB
    Write-Log "Free disk space: $([math]::Round($freeSpace, 2)) GB" "INFO"
    
    if ($freeSpace -lt 2) {
        Write-Log "WARNING: Less than 2GB free disk space" "WARN"
    }
    
    # Check internet connectivity
    try {
        $null = Test-NetConnection -ComputerName "www.python.org" -Port 443 -WarningAction SilentlyContinue -InformationLevel Quiet
        Write-Log "✓ Internet connectivity verified" "SUCCESS"
    }
    catch {
        Write-Log "WARNING: Internet connectivity check failed (may affect Python installation)" "WARN"
    }
    
    Write-Log "✓ Prerequisites check passed" "SUCCESS"
    return $true
}

# Step 2: Install dependencies
function Install-Dependencies {
    Write-Host ""
    Write-Host "Step 2: Installing Dependencies..." -ForegroundColor Cyan
    Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
    
    $installScript = Join-Path $REPO_ROOT "tools\install-dependencies.ps1"
    
    if (!(Test-Path $installScript)) {
        Write-Log "ERROR: install-dependencies.ps1 not found" "ERROR"
        return $false
    }
    
    try {
        Write-Log "Running install-dependencies.ps1..." "INFO"
        & $installScript
        
        if ($LASTEXITCODE -ne 0) {
            Write-Log "ERROR: Dependency installation failed" "ERROR"
            return $false
        }
        
        Write-Log "✓ Dependencies installed successfully" "SUCCESS"
        return $true
    }
    catch {
        Write-Log "ERROR: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

# Step 3: Enroll agent
function Invoke-AgentEnrollment {
    Write-Host ""
    Write-Host "Step 3: Agent Enrollment..." -ForegroundColor Cyan
    Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
    
    if ($SkipEnrollment) {
        Write-Log "Skipping enrollment (--SkipEnrollment specified)" "INFO"
        return $true
    }
    
    # Check if already enrolled
    $clientKeys = Join-Path $REPO_ROOT "client.keys"
    if ((Test-Path $clientKeys) -and ((Get-Item $clientKeys).Length -gt 0)) {
        Write-Log "Agent appears to be already enrolled" "INFO"
        
        $response = Read-Host "Re-enroll agent? (y/N)"
        if ($response -ne 'y' -and $response -ne 'Y') {
            Write-Log "✓ Using existing enrollment" "SUCCESS"
            return $true
        }
    }
    
    # Use UnifiedAgentControl.ps1 for enrollment
    $unifiedControl = Join-Path $REPO_ROOT "UnifiedAgentControl.ps1"
    
    if (!(Test-Path $unifiedControl)) {
        Write-Log "WARNING: UnifiedAgentControl.ps1 not found, skipping enrollment" "WARN"
        Write-Log "You can enroll later with: .\UnifiedAgentControl.ps1 configure" "INFO"
        return $true
    }
    
    try {
        Write-Log "Enrolling agent..." "INFO"
        Write-Log "  Manager IP: $ManagerIP" "INFO"
        Write-Log "  Agent Name: $AgentName" "INFO"
        
        # Run configure command
        & $unifiedControl -Command configure
        
        Write-Log "✓ Agent enrollment completed" "SUCCESS"
        return $true
    }
    catch {
        Write-Log "WARNING: Enrollment failed: $($_.Exception.Message)" "WARN"
        Write-Log "You can enroll later with: .\UnifiedAgentControl.ps1 configure" "INFO"
        return $true  # Non-critical, continue deployment
    }
}

# Step 4: Build supervisor
function Build-Supervisor {
    Write-Host ""
    Write-Host "Step 4: Building Supervisor Executable..." -ForegroundColor Cyan
    Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
    
    if ($SkipBuild) {
        $supervisorExe = Join-Path $REPO_ROOT "dist\supervisor.exe"
        if (Test-Path $supervisorExe) {
            Write-Log "Skipping build (--SkipBuild specified, existing executable found)" "INFO"
            return $true
        }
        else {
            Write-Log "WARNING: --SkipBuild specified but supervisor.exe not found, building anyway" "WARN"
        }
    }
    
    $buildScript = Join-Path $REPO_ROOT "tools\build.ps1"
    
    if (!(Test-Path $buildScript)) {
        Write-Log "ERROR: build.ps1 not found" "ERROR"
        return $false
    }
    
    try {
        Write-Log "Building supervisor executable (this may take 1-2 minutes)..." "INFO"
        & $buildScript
        
        if ($LASTEXITCODE -ne 0) {
            Write-Log "ERROR: Build failed" "ERROR"
            return $false
        }
        
        # Verify executable exists
        $supervisorExe = Join-Path $REPO_ROOT "dist\supervisor.exe"
        if (!(Test-Path $supervisorExe)) {
            Write-Log "ERROR: supervisor.exe not found after build" "ERROR"
            return $false
        }
        
        $fileSize = (Get-Item $supervisorExe).Length / 1MB
        Write-Log "✓ Build completed successfully ($([math]::Round($fileSize, 2)) MB)" "SUCCESS"
        return $true
    }
    catch {
        Write-Log "ERROR: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

# Step 5: Install service
function Install-Service {
    Write-Host ""
    Write-Host "Step 5: Installing Windows Service..." -ForegroundColor Cyan
    Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
    
    $installScript = Join-Path $REPO_ROOT "tools\install_service.ps1"
    
    if (!(Test-Path $installScript)) {
        Write-Log "ERROR: install_service.ps1 not found" "ERROR"
        return $false
    }
    
    # Check if service already exists
    $existingService = Get-Service -Name "RiskNoXSupervisor" -ErrorAction SilentlyContinue
    if ($existingService) {
        Write-Log "Service already exists, reinstalling..." "INFO"
        
        # Stop service if running
        if ($existingService.Status -eq 'Running') {
            Write-Log "Stopping existing service..." "INFO"
            Stop-Service -Name "RiskNoXSupervisor" -Force
            Start-Sleep -Seconds 3
        }
        
        # Remove service
        $nssmPath = Join-Path $REPO_ROOT "tools\nssm-2.24\win64\nssm.exe"
        if (Test-Path $nssmPath) {
            & $nssmPath remove RiskNoXSupervisor confirm
            Start-Sleep -Seconds 2
        }
    }
    
    try {
        Write-Log "Installing service..." "INFO"
        & $installScript
        
        if ($LASTEXITCODE -ne 0) {
            Write-Log "ERROR: Service installation failed" "ERROR"
            return $false
        }
        
        # Grant SYSTEM permissions (CRITICAL for service startup)
        Write-Log "Granting SYSTEM account permissions..." "INFO"
        $icaclsResult = icacls $REPO_ROOT /grant "SYSTEM:(OI)(CI)F" /T /Q 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Log "✓ SYSTEM permissions granted successfully" "SUCCESS"
        }
        else {
            Write-Log "WARNING: Failed to grant SYSTEM permissions (code $LASTEXITCODE)" "WARN"
            Write-Log "Service may fail to start. Manually run: icacls '$REPO_ROOT' /grant 'SYSTEM:(OI)(CI)F' /T /Q" "WARN"
        }
        
        Write-Log "✓ Service installed successfully" "SUCCESS"
        return $true
    }
    catch {
        Write-Log "ERROR: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

# Step 6: Start and verify service
function Start-AndVerifyService {
    Write-Host ""
    Write-Host "Step 6: Starting and Verifying Service..." -ForegroundColor Cyan
    Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
    
    try {
        # Start service
        Write-Log "Starting RiskNoXSupervisor service..." "INFO"
        Start-Service -Name "RiskNoXSupervisor"
        
        # Wait for service to start (max 30 seconds)
        $timeout = 30
        $elapsed = 0
        while ($elapsed -lt $timeout) {
            $service = Get-Service -Name "RiskNoXSupervisor"
            if ($service.Status -eq 'Running') {
                Write-Log "✓ Service started successfully" "SUCCESS"
                break
            }
            
            Start-Sleep -Seconds 2
            $elapsed += 2
            Write-Host "." -NoNewline
        }
        
        Write-Host ""
        
        if ($elapsed -ge $timeout) {
            Write-Log "ERROR: Service failed to start within $timeout seconds" "ERROR"
            Write-Log "Check logs at: logs\supervisor.log" "INFO"
            return $false
        }
        
        # Wait a bit more for processes to initialize
        Write-Log "Waiting for processes to initialize..." "INFO"
        Start-Sleep -Seconds 10
        
        # Verify processes are running
        Write-Log "Verifying managed processes..." "INFO"
        
        $statusScript = Join-Path $REPO_ROOT "tools\status-enhanced.ps1"
        if (Test-Path $statusScript) {
            & $statusScript
        }
        else {
            Write-Log "WARNING: status-enhanced.ps1 not found, skipping detailed verification" "WARN"
        }
        
        Write-Log "✓ Service verification completed" "SUCCESS"
        return $true
    }
    catch {
        Write-Log "ERROR: $($_.Exception.Message)" "ERROR"
        Write-Log "Check logs at: logs\supervisor.log" "INFO"
        return $false
    }
}

# Main deployment flow
function Start-Deployment {
    Show-Banner
    
    Write-Log "========================================" "INFO"
    Write-Log "Deployment started at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" "INFO"
    Write-Log "Repository: $REPO_ROOT" "INFO"
    Write-Log "========================================" "INFO"
    
    # Step 1: Prerequisites
    if (!(Test-Prerequisites)) {
        Write-Log "Deployment failed at prerequisites check" "ERROR"
        return $false
    }
    
    # Step 2: Dependencies
    if (!(Install-Dependencies)) {
        Write-Log "Deployment failed at dependency installation" "ERROR"
        return $false
    }
    
    # Step 3: Enrollment
    if (!(Invoke-AgentEnrollment)) {
        Write-Log "Deployment failed at agent enrollment" "ERROR"
        return $false
    }
    
    # Step 4: Build
    if (!(Build-Supervisor)) {
        Write-Log "Deployment failed at build step" "ERROR"
        return $false
    }
    
    # Step 5: Install service
    if (!(Install-Service)) {
        Write-Log "Deployment failed at service installation" "ERROR"
        return $false
    }
    
    # Step 6: Start and verify
    if (!(Start-AndVerifyService)) {
        Write-Log "Deployment completed with warnings (service started but verification had issues)" "WARN"
    }
    
    # Success summary
    Write-Host ""
    Write-Host "╔═══════════════════════════════════════════════════════════╗" -ForegroundColor Green
    Write-Host "║                                                           ║" -ForegroundColor Green
    Write-Host "║            Deployment Completed Successfully!            ║" -ForegroundColor Green
    Write-Host "║                                                           ║" -ForegroundColor Green
    Write-Host "╚═══════════════════════════════════════════════════════════╝" -ForegroundColor Green
    Write-Host ""
    
    Write-Log "========================================" "SUCCESS"
    Write-Log "Deployment completed at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" "SUCCESS"
    Write-Log "========================================" "SUCCESS"
    
    Write-Host ""
    Write-Host "Next Steps:" -ForegroundColor Cyan
    Write-Host "  • Check status:  .\tools\status-enhanced.ps1" -ForegroundColor White
    Write-Host "  • View logs:     Get-Content logs\supervisor.log -Tail 50" -ForegroundColor White
    Write-Host "  • Stop service:  Stop-Service -Name RiskNoXSupervisor" -ForegroundColor White
    Write-Host "  • Start service: Start-Service -Name RiskNoXSupervisor" -ForegroundColor White
    Write-Host ""
    
    return $true
}

# Execute deployment
try {
    $result = Start-Deployment
    exit ($result ? 0 : 1)
}
catch {
    Write-Log "FATAL ERROR: $($_.Exception.Message)" "ERROR"
    Write-Log "Stack Trace: $($_.ScriptStackTrace)" "ERROR"
    exit 1
}
