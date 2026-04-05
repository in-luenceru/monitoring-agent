#Requires -Version 5.1

<#
.SYNOPSIS
    RiskNoX Service Control - Unified control script for RiskNoX Monitoring Agent Supervisor Service.

.DESCRIPTION
    Complete service management tool that handles:
    - Installation: Installs dependencies, builds supervisor, configures service
    - Configuration: Enrolls and configures monitoring agent
    - Start: Starts service and verifies all processes (monitoring_agent, suricata)
    - Stop: Stops service (Admin only)
    - Status: Shows detailed status of service and all managed processes
    - Restart: Restarts the service
    - Uninstall: Removes service and cleans up

.PARAMETER Command
    Command to execute: install, configure, start, stop, status, restart, uninstall

.EXAMPLE
    .\RiskNoXServiceControl.ps1 install
    Installs all dependencies, builds supervisor, and installs Windows service

.EXAMPLE
    .\RiskNoXServiceControl.ps1 configure
    Configures monitoring agent enrollment (redirects to UnifiedAgentControl.ps1)

.EXAMPLE
    .\RiskNoXServiceControl.ps1 start
    Starts the service and verifies all processes are running

.EXAMPLE
    .\RiskNoXServiceControl.ps1 status
    Shows detailed status of service and all managed processes

.EXAMPLE
    .\RiskNoXServiceControl.ps1 stop
    Stops the service (requires administrator privileges)

.EXAMPLE
    .\RiskNoXServiceControl.ps1 restart
    Restarts the service

.EXAMPLE
    .\RiskNoXServiceControl.ps1 uninstall
    Completely removes the service
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true, Position=0)]
    [ValidateSet("install", "configure", "start", "stop", "status", "restart", "uninstall", "protect", "unprotect", "help")]
    [string]$Command,
    
    [Parameter(Mandatory=$false)]
    [string]$Password
)

# Configuration
$ErrorActionPreference = "Stop"
$REPO_ROOT = $PSScriptRoot
$SERVICE_NAME = "RiskNoXSupervisor"
$SERVICE_DISPLAY_NAME = "RiskNoX Monitoring Agent Supervisor"
$LOG_FILE = Join-Path $REPO_ROOT "logs\service-control.log"
$PASSWORD_FILE = Join-Path $REPO_ROOT "config\.service_password"

# Color output functions
function Write-Success { param([string]$Message) Write-Host "  ✓ $Message" -ForegroundColor Green }
function Write-Info { param([string]$Message) Write-Host "  ℹ $Message" -ForegroundColor Cyan }
function Write-Warning { param([string]$Message) Write-Host "  ⚠ $Message" -ForegroundColor Yellow }
function Write-Error { param([string]$Message) Write-Host "  ✗ $Message" -ForegroundColor Red }
function Write-Header { 
    param([string]$Message) 
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  $Message" -ForegroundColor White
    Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
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
    
    # Ensure log directory exists
    $logDir = Split-Path -Parent $LOG_FILE
    if (!(Test-Path $logDir)) {
        New-Item -ItemType Directory -Path $logDir -Force | Out-Null
    }
    
    Add-Content -Path $LOG_FILE -Value $logMessage -ErrorAction SilentlyContinue
}

# Initialize password file with default password
function Initialize-PasswordFile {
    $configDir = Join-Path $REPO_ROOT "config"
    if (!(Test-Path $configDir)) {
        New-Item -ItemType Directory -Path $configDir -Force | Out-Null
    }
    
    if (!(Test-Path $PASSWORD_FILE)) {
        # Default password: "RiskNoX@2024"
        $defaultPassword = "RiskNoX@2024"
        $hashedPassword = Get-FileHash -InputStream ([System.IO.MemoryStream]::new([System.Text.Encoding]::UTF8.GetBytes($defaultPassword))) -Algorithm SHA256
        Set-Content -Path $PASSWORD_FILE -Value $hashedPassword.Hash -Force
        Write-Log "Password file initialized with default password" "INFO"
    }
}

# Verify password
function Test-Password {
    param([string]$InputPassword)
    
    if (!(Test-Path $PASSWORD_FILE)) {
        Initialize-PasswordFile
    }
    
    $storedHash = Get-Content -Path $PASSWORD_FILE -Raw
    $storedHash = $storedHash.Trim()
    
    $inputHash = Get-FileHash -InputStream ([System.IO.MemoryStream]::new([System.Text.Encoding]::UTF8.GetBytes($InputPassword))) -Algorithm SHA256
    
    return ($inputHash.Hash -eq $storedHash)
}

# Change password
function Set-ServicePassword {
    param(
        [string]$CurrentPassword,
        [string]$NewPassword
    )
    
    if (!(Test-Password -InputPassword $CurrentPassword)) {
        Write-Error "Current password is incorrect"
        Write-Log "Failed password change attempt - incorrect current password" "WARN"
        return $false
    }
    
    if ($NewPassword.Length -lt 8) {
        Write-Error "New password must be at least 8 characters long"
        return $false
    }
    
    $hashedPassword = Get-FileHash -InputStream ([System.IO.MemoryStream]::new([System.Text.Encoding]::UTF8.GetBytes($NewPassword))) -Algorithm SHA256
    Set-Content -Path $PASSWORD_FILE -Value $hashedPassword.Hash -Force
    
    Write-Success "Password changed successfully"
    Write-Log "Service password changed" "SUCCESS"
    return $true
}

# Check administrator privileges
function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Check if service has protection enabled
function Test-ServiceProtection {
    param([string]$ServiceName)
    
    try {
        $sddlOutput = sc.exe sdshow $ServiceName 2>&1 | Out-String
        if ($LASTEXITCODE -eq 0) {
            # Check if SDDL contains deny rule for administrators (D;;WPDT;;;BA)
            if ($sddlOutput -match "D;.*WPDT.*BA") {
                return $true
            }
        }
        return $false
    }
    catch {
        return $false
    }
}

# Show banner
function Show-Banner {
    Write-Host ""
    Write-Host "╔═══════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║                                                           ║" -ForegroundColor Cyan
    Write-Host "║          RiskNoX Monitoring Agent - Service Control      ║" -ForegroundColor Cyan
    Write-Host "║                                                           ║" -ForegroundColor Cyan
    Write-Host "╚═══════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
}

# Install command - Full installation
function Invoke-Install {
    Write-Header "INSTALLING RiskNoX Monitoring Agent Service"
    
    if (!(Test-Administrator)) {
        Write-Error "Administrator privileges required for installation"
        Write-Info "Please run: Start-Process powershell -Verb RunAs -ArgumentList '-File ""$PSCommandPath"" install'"
        Write-Log "Installation failed: Not running as administrator" "ERROR"
        return $false
    }
    
    Write-Log "Starting installation process" "INFO"
    
    # Step 1: Check prerequisites
    Write-Host ""
    Write-Info "Step 1/5: Checking prerequisites..."
    
    $os = Get-CimInstance -ClassName Win32_OperatingSystem
    $osVersion = [System.Environment]::OSVersion.Version
    
    if ($osVersion.Major -lt 10) {
        Write-Error "Windows 10 or later is required"
        Write-Log "Installation failed: Unsupported Windows version" "ERROR"
        return $false
    }
    
    Write-Success "Prerequisites check passed"
    Write-Log "Prerequisites check passed" "SUCCESS"
    
    # Step 2: Install dependencies (Python + packages)
    Write-Host ""
    Write-Info "Step 2/5: Installing dependencies..."
    
    $installDepsScript = Join-Path $REPO_ROOT "tools\install-dependencies.ps1"
    if (!(Test-Path $installDepsScript)) {
        Write-Error "install-dependencies.ps1 not found"
        Write-Log "Installation failed: install-dependencies.ps1 not found" "ERROR"
        return $false
    }
    
    try {
        & $installDepsScript
        if ($LASTEXITCODE -ne 0) {
            Write-Error "Dependency installation failed"
            Write-Log "Installation failed: Dependency installation failed" "ERROR"
            return $false
        }
        Write-Success "Dependencies installed successfully"
        Write-Log "Dependencies installed" "SUCCESS"
    }
    catch {
        Write-Error "Failed to install dependencies: $($_.Exception.Message)"
        Write-Log "Installation failed: $($_.Exception.Message)" "ERROR"
        return $false
    }
    
    # Step 3: Build supervisor executable
    Write-Host ""
    Write-Info "Step 3/5: Building supervisor executable (this may take 1-2 minutes)..."
    
    $buildScript = Join-Path $REPO_ROOT "tools\build.ps1"
    if (!(Test-Path $buildScript)) {
        Write-Error "build.ps1 not found"
        Write-Log "Installation failed: build.ps1 not found" "ERROR"
        return $false
    }
    
    try {
        & $buildScript -SkipTest
        if ($LASTEXITCODE -ne 0) {
            Write-Error "Build failed"
            Write-Log "Installation failed: Build failed" "ERROR"
            return $false
        }
        
        $supervisorExe = Join-Path $REPO_ROOT "dist\supervisor.exe"
        if (!(Test-Path $supervisorExe)) {
            Write-Error "supervisor.exe not found after build"
            Write-Log "Installation failed: supervisor.exe not found" "ERROR"
            return $false
        }
        
        $fileSize = (Get-Item $supervisorExe).Length / 1MB
        Write-Success "Build completed ($([math]::Round($fileSize, 2)) MB)"
        Write-Log "Build completed successfully" "SUCCESS"
    }
    catch {
        Write-Error "Build failed: $($_.Exception.Message)"
        Write-Log "Installation failed: $($_.Exception.Message)" "ERROR"
        return $false
    }
    
    # Step 4: Install Windows service
    Write-Host ""
    Write-Info "Step 4/5: Installing Windows service..."
    
    # Check if service already exists
    $existingService = Get-Service -Name $SERVICE_NAME -ErrorAction SilentlyContinue
    if ($existingService) {
        Write-Warning "Service already exists, reinstalling..."
        Write-Log "Service already exists, reinstalling" "WARN"
        
        if ($existingService.Status -eq 'Running') {
            Write-Info "Stopping existing service..."
            Stop-Service -Name $SERVICE_NAME -Force
            Start-Sleep -Seconds 3
        }
        
        $nssmPath = Join-Path $REPO_ROOT "tools\nssm\win64\nssm.exe"
        if (Test-Path $nssmPath) {
            & $nssmPath remove $SERVICE_NAME confirm | Out-Null
            Start-Sleep -Seconds 2
        }
    }
    
    $installServiceScript = Join-Path $REPO_ROOT "tools\install_service.ps1"
    if (!(Test-Path $installServiceScript)) {
        Write-Error "install_service.ps1 not found"
        Write-Log "Installation failed: install_service.ps1 not found" "ERROR"
        return $false
    }
    
    try {
        & $installServiceScript
        if ($LASTEXITCODE -ne 0) {
            Write-Error "Service installation failed"
            Write-Log "Installation failed: Service installation failed" "ERROR"
            return $false
        }
        Write-Success "Service installed successfully"
        Write-Log "Service installed" "SUCCESS"
    }
    catch {
        Write-Error "Service installation failed: $($_.Exception.Message)"
        Write-Log "Installation failed: $($_.Exception.Message)" "ERROR"
        return $false
    }
    
    # Step 5: Configure permissions and security
    Write-Host ""
    Write-Info "Step 5/5: Configuring permissions and security..."
    
    # Grant SYSTEM account permissions
    Write-Info "Granting SYSTEM account permissions..."
    try {
        $icaclsResult = icacls $REPO_ROOT /grant "SYSTEM:(OI)(CI)F" /T /Q 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Success "SYSTEM permissions granted"
            Write-Log "SYSTEM permissions granted" "SUCCESS"
        }
        else {
            Write-Warning "Failed to grant SYSTEM permissions (service may fail to start)"
            Write-Log "Failed to grant SYSTEM permissions" "WARN"
        }
    }
    catch {
        Write-Warning "Permission configuration failed: $($_.Exception.Message)"
        Write-Log "Permission configuration failed: $($_.Exception.Message)" "WARN"
    }
    
    # Apply advanced service protection
    Write-Info "Applying advanced service protection (LocalSystem + SDDL)..."
    try {
        # Set LocalSystem account (highest privileges)
        $configResult = sc.exe config $SERVICE_NAME obj= LocalSystem 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Success "Service configured to run as LocalSystem"
            Write-Log "Service configured as LocalSystem" "SUCCESS"
        }
        
        # Apply SDDL protection (deny administrators from stopping service)
        $sddl = "D:(D;;WPDT;;;BA)(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)"
        $sddlResult = sc.exe sdset $SERVICE_NAME $sddl 2>&1
        
        if ($LASTEXITCODE -eq 0) {
            Write-Success "SDDL protection applied (administrators cannot stop service)"
            Write-Log "SDDL protection applied" "SUCCESS"
        }
        else {
            Write-Warning "Failed to apply SDDL protection: $sddlResult"
            Write-Log "SDDL protection failed: $sddlResult" "WARN"
        }
        
        # Configure automatic restart on any failure
        $failureResult = sc.exe failure $SERVICE_NAME reset= 0 actions= restart/0/restart/0/restart/0 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-Success "Auto-restart on failure configured (0ms delay, unlimited)"
            Write-Log "Auto-restart configured" "SUCCESS"
        }
        
        Write-Success "Service protection applied successfully"
        Write-Warning "Note: Administrators cannot stop this service through normal means"
        Write-Info "      Use this script to manage the service: .\RiskNoXServiceControl.ps1 stop"
        Write-Log "Service protection completed" "SUCCESS"
    }
    catch {
        Write-Warning "Service protection configuration failed: $($_.Exception.Message)"
        Write-Log "Service protection failed: $($_.Exception.Message)" "WARN"
    }
    
    # Installation complete
    Write-Host ""
    Write-Host "╔═══════════════════════════════════════════════════════════╗" -ForegroundColor Green
    Write-Host "║                                                           ║" -ForegroundColor Green
    Write-Host "║         Installation Completed Successfully!             ║" -ForegroundColor Green
    Write-Host "║                                                           ║" -ForegroundColor Green
    Write-Host "╚═══════════════════════════════════════════════════════════╝" -ForegroundColor Green
    Write-Host ""
    
    Write-Info "Next steps:"
    Write-Host "    1. Configure agent:  .\RiskNoXServiceControl.ps1 configure" -ForegroundColor White
    Write-Host "    2. Start service:    .\RiskNoXServiceControl.ps1 start" -ForegroundColor White
    Write-Host "    3. Check status:     .\RiskNoXServiceControl.ps1 status" -ForegroundColor White
    Write-Host ""
    
    Write-Host "IMPORTANT SECURITY NOTICE:" -ForegroundColor Yellow
    Write-Host "  • Service is protected with LocalSystem privileges" -ForegroundColor White
    Write-Host "  • Administrators CANNOT stop service through Windows" -ForegroundColor White
    Write-Host "  • Use this script to manage the service:" -ForegroundColor White
    Write-Host "    - Stop:  .\RiskNoXServiceControl.ps1 stop" -ForegroundColor Cyan
    Write-Host "    - Start: .\RiskNoXServiceControl.ps1 start" -ForegroundColor Cyan
    Write-Host "  • Service auto-restarts on failure" -ForegroundColor White
    Write-Host ""
    
    Write-Log "Installation completed successfully" "SUCCESS"
    return $true
}

# Configure command - Redirects to UnifiedAgentControl.ps1
function Invoke-Configure {
    Write-Header "CONFIGURING RiskNoX Monitoring Agent"
    
    Write-Log "Starting configuration process" "INFO"
    
    $unifiedControl = Join-Path $REPO_ROOT "UnifiedAgentControl.ps1"
    
    if (!(Test-Path $unifiedControl)) {
        Write-Error "UnifiedAgentControl.ps1 not found"
        Write-Info "Please ensure UnifiedAgentControl.ps1 exists in: $REPO_ROOT"
        Write-Log "Configuration failed: UnifiedAgentControl.ps1 not found" "ERROR"
        return $false
    }
    
    Write-Info "Redirecting to UnifiedAgentControl.ps1 for agent configuration..."
    Write-Host ""
    
    try {
        # Execute UnifiedAgentControl.ps1 configure and show its output
        # UnifiedAgentControl.ps1 uses -Action parameter, not -Command
        & $unifiedControl -Action configure
        
        Write-Host ""
        Write-Success "Configuration completed"
        Write-Log "Configuration completed via UnifiedAgentControl.ps1" "SUCCESS"
        
        Write-Host ""
        Write-Info "Next step: Start the service with: .\RiskNoXServiceControl.ps1 start"
        Write-Host ""
        
        return $true
    }
    catch {
        Write-Error "Configuration failed: $($_.Exception.Message)"
        Write-Log "Configuration failed: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

# Start command - Starts service and verifies all processes
function Invoke-Start {
    Write-Header "STARTING RiskNoX Monitoring Agent Service"
    
    # Initialize password file if it doesn't exist
    Initialize-PasswordFile
    
    # Validate password
    if ([string]::IsNullOrEmpty($Password)) {
        Write-Error "Password is required to start the service"
        Write-Host ""
        Write-Info "Default password: RiskNoX@2024"
        Write-Host "Usage: .\RiskNoXServiceControl.ps1 start -Password 'YourPassword'" -ForegroundColor Yellow
        Write-Host ""
        Write-Log "Start attempt without password" "WARN"
        return $false
    }
    
    if (!(Test-Password -InputPassword $Password)) {
        Write-Error "Incorrect password"
        Write-Log "Start attempt with incorrect password" "WARN"
        return $false
    }
    
    Write-Log "Starting service (password validated)" "INFO"
    
    # Check if service exists
    $service = Get-Service -Name $SERVICE_NAME -ErrorAction SilentlyContinue
    if (!$service) {
        Write-Error "Service not installed"
        Write-Info "Install service first with: .\RiskNoXServiceControl.ps1 install"
        Write-Log "Start failed: Service not installed" "ERROR"
        return $false
    }
    
    # Check if already running
    if ($service.Status -eq 'Running') {
        Write-Success "Service is already running"
        Write-Log "Service already running" "INFO"
        
        # Still verify processes
        Write-Host ""
        Write-Info "Verifying managed processes..."
        Start-Sleep -Seconds 2
        Invoke-Status
        return $true
    }
    
    # Start the service
    Write-Info "Starting $SERVICE_DISPLAY_NAME..."
    try {
        Start-Service -Name $SERVICE_NAME -ErrorAction Stop
        Write-Success "Service start command issued"
        Write-Log "Service start command issued" "INFO"
    }
    catch {
        Write-Error "Failed to start service: $($_.Exception.Message)"
        Write-Info "Check logs at: logs\supervisor.log"
        Write-Log "Service start failed: $($_.Exception.Message)" "ERROR"
        return $false
    }
    
    # Wait for service to start (max 30 seconds)
    Write-Info "Waiting for service to start (this may take up to 30 seconds)..."
    $timeout = 30
    $elapsed = 0
    
    while ($elapsed -lt $timeout) {
        $service = Get-Service -Name $SERVICE_NAME
        if ($service.Status -eq 'Running') {
            Write-Success "Service started successfully"
            Write-Log "Service started successfully" "SUCCESS"
            break
        }
        
        Start-Sleep -Seconds 2
        $elapsed += 2
        Write-Host "." -NoNewline
    }
    Write-Host ""
    
    if ($elapsed -ge $timeout) {
        Write-Error "Service failed to start within $timeout seconds"
        Write-Info "Check logs at: logs\supervisor.log"
        Write-Log "Service start timeout" "ERROR"
        return $false
    }
    
    # Reapply service protection after start
    Write-Info "Reapplying service protection..."
    try {
        # Apply SDDL protection (deny administrators from stopping service)
        $sddl = "D:(D;;WPDT;;;BA)(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)"
        sc.exe sdset $SERVICE_NAME $sddl 2>&1 | Out-Null
        
        if ($LASTEXITCODE -eq 0) {
            Write-Success "Service protection reapplied"
            Write-Log "SDDL protection reapplied after start" "SUCCESS"
        }
        else {
            Write-Warning "Could not reapply protection"
            Write-Log "Failed to reapply SDDL protection" "WARN"
        }
    }
    catch {
        Write-Warning "Failed to reapply service protection: $($_.Exception.Message)"
        Write-Log "SDDL reapplication failed: $($_.Exception.Message)" "WARN"
    }
    
    # Wait for processes to initialize
    Write-Info "Waiting for managed processes to initialize..."
    Start-Sleep -Seconds 10
    
    # Verify all managed processes: monitoring_agent, suricata
    Write-Host ""
    Write-Info "Verifying managed processes..."
    Write-Host ""
    
    $allProcessesRunning = $true
    
    # Check Control API
    $tokenFile = Join-Path $REPO_ROOT "config\supervisor_token.txt"
    if (Test-Path $tokenFile) {
        try {
            $token = (Get-Content $tokenFile -Raw).Trim()
            $headers = @{ "Authorization" = "Bearer $token" }
            
            $response = Invoke-RestMethod -Uri "http://127.0.0.1:8765/api/status" `
                                           -Method GET `
                                           -Headers $headers `
                                           -TimeoutSec 10 `
                                           -ErrorAction Stop
            
            if ($response -and $response.processes) {
                $requiredProcesses = @("monitoring_agent", "suricata_ids")
                
                foreach ($procName in $requiredProcesses) {
                    $proc = $response.processes | Where-Object { $_.name -eq $procName }
                    
                    if ($proc) {
                        $statusSymbol = if ($proc.state -eq "running") { "✓" } else { "✗" }
                        $statusColor = if ($proc.state -eq "running") { "Green" } else { "Red" }
                        
                        Write-Host "  $statusSymbol " -NoNewline -ForegroundColor $statusColor
                        Write-Host "$($proc.name): " -NoNewline
                        Write-Host $proc.state.ToUpper() -ForegroundColor $statusColor
                        
                        if ($proc.state -ne "running") {
                            $allProcessesRunning = $false
                            Write-Log "$($proc.name) not running: $($proc.state)" "WARN"
                        }
                        
                        if ($proc.pid -and $proc.pid -gt 0) {
                            Write-Host "      PID: $($proc.pid)" -ForegroundColor Gray
                        }
                    }
                    else {
                        Write-Host "  ✗ ${procName}: NOT FOUND" -ForegroundColor Red
                        $allProcessesRunning = $false
                        Write-Log "$procName not found in supervisor status" "ERROR"
                    }
                }
                
                Write-Host ""
                
                if ($allProcessesRunning) {
                    Write-Success "All managed processes are running"
                    Write-Log "All managed processes verified running" "SUCCESS"
                }
                else {
                    Write-Warning "Some processes are not running properly"
                    Write-Info "Check logs at: logs\supervisor.log"
                    Write-Info "View detailed status: .\RiskNoXServiceControl.ps1 status"
                    Write-Log "Some processes not running" "WARN"
                }
            }
            else {
                Write-Warning "Could not retrieve process status from Control API"
                Write-Log "Control API returned no process data" "WARN"
            }
        }
        catch {
            Write-Warning "Could not query Control API: $($_.Exception.Message)"
            Write-Info "Service may still be initializing. Check status in a few seconds."
            Write-Log "Control API query failed: $($_.Exception.Message)" "WARN"
        }
    }
    else {
        Write-Warning "Control API token not found"
        Write-Info "Service may still be initializing. Check status in a few seconds."
        Write-Log "Control API token not found" "WARN"
    }
    
    Write-Host ""
    Write-Info "Service is configured to:"
    Write-Host "    • Start automatically on system boot" -ForegroundColor White
    Write-Host "    • Restart automatically if processes crash" -ForegroundColor White
    Write-Host "    • Run until explicitly stopped by administrator" -ForegroundColor White
    Write-Host ""
    
    Write-Info "Use '.\RiskNoXServiceControl.ps1 status' for detailed status"
    Write-Host ""
    
    return $allProcessesRunning
}

# Stop command - Stops service (admin only)
function Invoke-Stop {
    Write-Header "STOPPING RiskNoX Monitoring Agent Service"
    
    # Initialize password file if it doesn't exist
    Initialize-PasswordFile
    
    # Validate password
    if ([string]::IsNullOrEmpty($Password)) {
        Write-Error "Password is required to stop the service"
        Write-Host ""
        Write-Info "Default password: RiskNoX@2024"
        Write-Host "Usage: .\RiskNoXServiceControl.ps1 stop -Password 'YourPassword'" -ForegroundColor Yellow
        Write-Host ""
        Write-Log "Stop attempt without password" "WARN"
        return $false
    }
    
    if (!(Test-Password -InputPassword $Password)) {
        Write-Error "Incorrect password"
        Write-Log "Stop attempt with incorrect password" "WARN"
        return $false
    }
    
    if (!(Test-Administrator)) {
        Write-Error "Administrator privileges required to stop service"
        Write-Info "Please run: Start-Process powershell -Verb RunAs -ArgumentList '-File ""$PSCommandPath"" stop'"
        Write-Log "Stop failed: Not running as administrator" "ERROR"
        return $false
    }
    
    Write-Log "Stopping service" "INFO"
    
    $service = Get-Service -Name $SERVICE_NAME -ErrorAction SilentlyContinue
    if (!$service) {
        Write-Error "Service not installed"
        Write-Log "Stop failed: Service not installed" "ERROR"
        return $false
    }
    
    if ($service.Status -eq 'Stopped') {
        Write-Success "Service is already stopped"
        Write-Log "Service already stopped" "INFO"
        return $true
    }
    
    Write-Info "Stopping $SERVICE_DISPLAY_NAME..."
    Write-Info "This will stop all managed processes (monitoring_agent, suricata)..."
    Write-Host ""
    
    # First, temporarily remove SDDL protection to allow stopping
    Write-Info "Temporarily removing service protection to allow stop..."
    try {
        # Apply standard SDDL that allows administrators full control
        $standardSDDL = "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)"
        sc.exe sdset $SERVICE_NAME $standardSDDL 2>&1 | Out-Null
        
        if ($LASTEXITCODE -eq 0) {
            Write-Success "Protection temporarily removed"
            Write-Log "SDDL protection removed for stop operation" "INFO"
        }
        else {
            Write-Warning "Could not remove protection, attempting stop anyway..."
            Write-Log "Failed to remove SDDL protection" "WARN"
        }
    }
    catch {
        Write-Warning "Failed to modify service permissions: $($_.Exception.Message)"
        Write-Log "SDDL modification failed: $($_.Exception.Message)" "WARN"
    }
    
    # Now stop the service
    try {
        Stop-Service -Name $SERVICE_NAME -Force -ErrorAction Stop
        
        # Wait for service to stop
        $timeout = 30
        $elapsed = 0
        
        while ($elapsed -lt $timeout) {
            $service = Get-Service -Name $SERVICE_NAME
            if ($service.Status -eq 'Stopped') {
                Write-Success "Service stopped successfully"
                Write-Log "Service stopped successfully" "SUCCESS"
                Write-Host ""
                
                Write-Info "Service is now stopped. Protection will be reapplied on next start."
                Write-Host ""
                return $true
            }
            
            Start-Sleep -Seconds 2
            $elapsed += 2
            Write-Host "." -NoNewline
        }
        Write-Host ""
        
        if ($elapsed -ge $timeout) {
            Write-Error "Service failed to stop within $timeout seconds"
            Write-Log "Service stop timeout" "ERROR"
            
            # Try to reapply protection even if stop failed
            Write-Warning "Reapplying service protection..."
            $sddl = "D:(D;;WPDT;;;BA)(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)"
            sc.exe sdset $SERVICE_NAME $sddl 2>&1 | Out-Null
            
            return $false
        }
    }
    catch {
        Write-Error "Failed to stop service: $($_.Exception.Message)"
        Write-Log "Service stop failed: $($_.Exception.Message)" "ERROR"
        
        # Try to reapply protection even if stop failed
        Write-Warning "Reapplying service protection..."
        $sddl = "D:(D;;WPDT;;;BA)(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)"
        sc.exe sdset $SERVICE_NAME $sddl 2>&1 | Out-Null
        
        return $false
    }
}

# Status command - Shows detailed status
function Invoke-Status {
    Write-Header "RiskNoX Monitoring Agent Service Status"
    
    Write-Log "Checking status" "INFO"
    
    # Check if service exists
    $service = Get-Service -Name $SERVICE_NAME -ErrorAction SilentlyContinue
    if (!$service) {
        Write-Error "Service not installed"
        Write-Info "Install service with: .\RiskNoXServiceControl.ps1 install"
        Write-Log "Status check: Service not installed" "INFO"
        return $false
    }
    
    # Service status
    Write-Host ""
    Write-Info "Service Status:"
    
    $statusColor = switch ($service.Status) {
        'Running' { "Green" }
        'Stopped' { "Red" }
        default { "Yellow" }
    }
    
    Write-Host "  Service:        " -NoNewline
    Write-Host $service.Status.ToString().ToUpper() -ForegroundColor $statusColor
    Write-Host "  Start Type:     $($service.StartType)" -ForegroundColor Gray
    Write-Host "  Display Name:   $($service.DisplayName)" -ForegroundColor Gray
    
    # Check protection status
    $isProtected = Test-ServiceProtection -ServiceName $SERVICE_NAME
    Write-Host "  Protection:     " -NoNewline
    if ($isProtected) {
        Write-Host "ENABLED" -ForegroundColor Green
        Write-Host "                  (Admins cannot stop via Windows)" -ForegroundColor Gray
    }
    else {
        Write-Host "DISABLED" -ForegroundColor Yellow
        Write-Host "                  (Use this script to reapply)" -ForegroundColor Gray
    }
    
    # Check if running as LocalSystem
    try {
        $wmiService = Get-WmiObject -Class Win32_Service -Filter "Name='$SERVICE_NAME'" -ErrorAction SilentlyContinue
        if ($wmiService) {
            Write-Host "  Account:        $($wmiService.StartName)" -ForegroundColor Gray
        }
    }
    catch { }
    
    Write-Host ""
    
    if ($service.Status -ne 'Running') {
        Write-Warning "Service is not running"
        Write-Info "Start service with: .\RiskNoXServiceControl.ps1 start"
        Write-Host ""
        return $false
    }
    
    # Port check
    Write-Info "Port Status:"
    try {
        $backendPort = Test-NetConnection -ComputerName 127.0.0.1 -Port 5000 -WarningAction SilentlyContinue -InformationLevel Quiet
        $controlPort = Test-NetConnection -ComputerName 127.0.0.1 -Port 8765 -WarningAction SilentlyContinue -InformationLevel Quiet
        
        $backendSymbol = if ($backendPort) { "✓" } else { "✗" }
        $backendColor = if ($backendPort) { "Green" } else { "Red" }
        Write-Host "  $backendSymbol Backend API (5000):  " -NoNewline -ForegroundColor $backendColor
        Write-Host $(if ($backendPort) { "LISTENING" } else { "NOT LISTENING" }) -ForegroundColor $backendColor
        
        $controlSymbol = if ($controlPort) { "✓" } else { "✗" }
        $controlColor = if ($controlPort) { "Green" } else { "Red" }
        Write-Host "  $controlSymbol Control API (8765):  " -NoNewline -ForegroundColor $controlColor
        Write-Host $(if ($controlPort) { "LISTENING" } else { "NOT LISTENING" }) -ForegroundColor $controlColor
    }
    catch {
        Write-Warning "Port check failed"
    }
    Write-Host ""
    
    # Check enrollment
    Write-Info "Agent Enrollment:"
    $clientKeys = Join-Path $REPO_ROOT "client.keys"
    if ((Test-Path $clientKeys) -and ((Get-Item $clientKeys).Length -gt 0)) {
        Write-Success "Client keys configured"
        
        $ossecConf = Join-Path $REPO_ROOT "ossec.conf"
        if (Test-Path $ossecConf) {
            try {
                [xml]$ossecXml = Get-Content $ossecConf
                $managerIP = $ossecXml.ossec_config.client.server.address
                if ($managerIP) {
                    Write-Host "    Manager IP: $managerIP" -ForegroundColor Gray
                }
            }
            catch { }
        }
    }
    else {
        Write-Warning "Client keys not configured"
        Write-Info "    Configure with: .\RiskNoXServiceControl.ps1 configure"
    }
    Write-Host ""
    
    # Query Control API for detailed process status
    Write-Info "Managed Processes:"
    $tokenFile = Join-Path $REPO_ROOT "config\supervisor_token.txt"
    
    if (!(Test-Path $tokenFile)) {
        Write-Warning "Control API token not found"
        Write-Info "Service may still be initializing"
        Write-Host ""
        return $false
    }
    
    try {
        $token = (Get-Content $tokenFile -Raw).Trim()
        $headers = @{ "Authorization" = "Bearer $token" }
        
        $response = Invoke-RestMethod -Uri "http://127.0.0.1:8765/api/status" `
                                       -Method GET `
                                       -Headers $headers `
                                       -TimeoutSec 10 `
                                       -ErrorAction Stop
        
        if ($response -and $response.processes) {
            Write-Host ""
            
            foreach ($process in $response.processes) {
                $stateColor = switch ($process.state) {
                    "running"  { "Green" }
                    "starting" { "Yellow" }
                    "backoff"  { "Yellow" }
                    "failed"   { "Red" }
                    "stopped"  { "Gray" }
                    default    { "White" }
                }
                
                $stateSymbol = if ($process.state -eq "running") { "✓" } else { "✗" }
                
                Write-Host "  $stateSymbol " -NoNewline -ForegroundColor $stateColor
                Write-Host "$($process.name):" -ForegroundColor White
                Write-Host "      State:          " -NoNewline
                Write-Host $process.state.ToUpper() -ForegroundColor $stateColor
                
                if ($process.pid -and $process.pid -gt 0) {
                    Write-Host "      PID:            $($process.pid)" -ForegroundColor Gray
                    
                    # Get process uptime
                    try {
                        $proc = Get-Process -Id $process.pid -ErrorAction SilentlyContinue
                        if ($proc) {
                            $uptime = (Get-Date) - $proc.StartTime
                            $uptimeStr = if ($uptime.TotalDays -ge 1) {
                                "$([int]$uptime.TotalDays)d $($uptime.Hours)h $($uptime.Minutes)m"
                            } elseif ($uptime.TotalHours -ge 1) {
                                "$($uptime.Hours)h $($uptime.Minutes)m"
                            } else {
                                "$($uptime.Minutes)m $($uptime.Seconds)s"
                            }
                            Write-Host "      Uptime:         $uptimeStr" -ForegroundColor Gray
                        }
                    }
                    catch { }
                }
                
                if ($process.restart_count -ne $null) {
                    $restartColor = if ($process.restart_count -gt 0) { "Yellow" } else { "Gray" }
                    Write-Host "      Restart Count:  $($process.restart_count)" -ForegroundColor $restartColor
                }
                
                Write-Host ""
            }
            
            # Summary
            $runningCount = ($response.processes | Where-Object { $_.state -eq "running" }).Count
            $totalCount = $response.processes.Count
            
            Write-Host "  Summary:" -ForegroundColor White
            Write-Host "    Total Processes:  $totalCount" -ForegroundColor Gray
            Write-Host "    Running:          " -NoNewline
            
            if ($runningCount -eq $totalCount) {
                Write-Host "$runningCount" -ForegroundColor Green
            }
            else {
                Write-Host "$runningCount" -ForegroundColor Yellow
            }
            
            Write-Host ""
        }
        else {
            Write-Warning "No processes reported by supervisor"
            Write-Host ""
        }
    }
    catch {
        Write-Warning "Could not query Control API: $($_.Exception.Message)"
        Write-Info "Service may still be initializing"
        Write-Host ""
    }
    
    # Log locations
    Write-Info "Log Files:"
    Write-Host "    Supervisor:     logs\supervisor.log" -ForegroundColor Gray
    Write-Host "    Monitoring:     logs\monitoring-agent.log" -ForegroundColor Gray
    Write-Host "    Agent:          logs\monitoring_agent_stdout.log" -ForegroundColor Gray
    Write-Host "    Suricata:       suricata/log/suricata.log" -ForegroundColor Gray
    
    return $true
}

# Restart command
function Invoke-Restart {
    Write-Header "RESTARTING RiskNoX Monitoring Agent Service"
    
    Write-Log "Restarting service" "INFO"
    
    # Stop service
    $stopResult = Invoke-Stop
    if (!$stopResult) {
        Write-Error "Failed to stop service"
        return $false
    }
    
    Write-Info "Waiting 5 seconds before restart..."
    Start-Sleep -Seconds 5
    
    # Start service
    $startResult = Invoke-Start
    return $startResult
}

# Uninstall command
function Invoke-Uninstall {
    Write-Header "UNINSTALLING RiskNoX Monitoring Agent Service"
    
    if (!(Test-Administrator)) {
        Write-Error "Administrator privileges required for uninstallation"
        Write-Info "Please run: Start-Process powershell -Verb RunAs -ArgumentList '-File ""$PSCommandPath"" uninstall'"
        Write-Log "Uninstall failed: Not running as administrator" "ERROR"
        return $false
    }
    
    Write-Log "Starting uninstallation process" "INFO"
    Write-Warning "This will completely remove the service"
    Write-Host ""
    
    $confirm = Read-Host "Are you sure you want to uninstall? (yes/no)"
    if ($confirm -ne "yes") {
        Write-Info "Uninstall cancelled"
        return $false
    }
    
    Write-Host ""
    
    $service = Get-Service -Name $SERVICE_NAME -ErrorAction SilentlyContinue
    if (!$service) {
        Write-Warning "Service not found"
        return $true
    }
    
    # Remove service protection before uninstalling
    Write-Info "Removing service protection..."
    try {
        # Apply standard SDDL that allows administrators full control
        $standardSDDL = "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)"
        sc.exe sdset $SERVICE_NAME $standardSDDL 2>&1 | Out-Null
        
        if ($LASTEXITCODE -eq 0) {
            Write-Success "Service protection removed"
            Write-Log "SDDL protection removed for uninstall" "INFO"
        }
        else {
            Write-Warning "Could not remove protection, attempting uninstall anyway..."
            Write-Log "Failed to remove SDDL protection" "WARN"
        }
    }
    catch {
        Write-Warning "Failed to modify service permissions: $($_.Exception.Message)"
        Write-Log "SDDL modification failed: $($_.Exception.Message)" "WARN"
    }
    
    # Stop service if running
    if ($service.Status -eq 'Running') {
        Write-Info "Stopping service..."
        try {
            Stop-Service -Name $SERVICE_NAME -Force -ErrorAction Stop
            Start-Sleep -Seconds 3
            Write-Success "Service stopped"
        }
        catch {
            Write-Warning "Could not stop service: $($_.Exception.Message)"
            Write-Info "Attempting to force uninstall..."
        }
    }
    
    # Remove service using NSSM
    Write-Info "Removing service..."
    $nssmPath = Join-Path $REPO_ROOT "tools\nssm\win64\nssm.exe"
    if (Test-Path $nssmPath) {
        & $nssmPath remove $SERVICE_NAME confirm 2>&1 | Out-Null
        Start-Sleep -Seconds 2
        
        # Verify service is actually removed
        $serviceCheck = Get-Service -Name $SERVICE_NAME -ErrorAction SilentlyContinue
        if (!$serviceCheck) {
            Write-Success "Service removed successfully"
            Write-Log "Service uninstalled" "SUCCESS"
        }
        else {
            Write-Warning "Service may not have been removed completely"
            Write-Info "Attempting manual removal..."
            
            # Try using sc.exe as fallback
            sc.exe delete $SERVICE_NAME 2>&1 | Out-Null
            Start-Sleep -Seconds 2
            
            $serviceCheck2 = Get-Service -Name $SERVICE_NAME -ErrorAction SilentlyContinue
            if (!$serviceCheck2) {
                Write-Success "Service removed via sc.exe"
                Write-Log "Service uninstalled via sc.exe" "SUCCESS"
            }
            else {
                Write-Error "Could not remove service"
                Write-Info "You may need to manually remove: sc.exe delete $SERVICE_NAME"
                Write-Log "Service removal failed" "ERROR"
                return $false
            }
        }
    }
    else {
        Write-Error "NSSM not found at: $nssmPath"
        Write-Info "Expected NSSM location: $nssmPath"
        Write-Info "Attempting removal with sc.exe..."
        
        # Try using sc.exe directly
        sc.exe delete $SERVICE_NAME 2>&1 | Out-Null
        Start-Sleep -Seconds 2
        
        $serviceCheck = Get-Service -Name $SERVICE_NAME -ErrorAction SilentlyContinue
        if (!$serviceCheck) {
            Write-Success "Service removed via sc.exe"
            Write-Log "Service uninstalled via sc.exe" "SUCCESS"
        }
        else {
            Write-Error "Could not remove service"
            Write-Log "Service removal failed" "ERROR"
            return $false
        }
    }
    
    Write-Host ""
    Write-Success "Service has been uninstalled successfully"
    Write-Info "Note: Application files have not been deleted"
    Write-Info "      To remove completely, delete the entire directory"
    Write-Host ""
    
    return $true
}

# Protect command - Apply service protection
function Invoke-Protect {
    Write-Header "APPLYING Service Protection"
    
    if (!(Test-Administrator)) {
        Write-Error "Administrator privileges required"
        Write-Info "Please run: Start-Process powershell -Verb RunAs -ArgumentList '-File ""$PSCommandPath"" protect'"
        Write-Log "Protect failed: Not running as administrator" "ERROR"
        return $false
    }
    
    Write-Log "Applying service protection" "INFO"
    
    $service = Get-Service -Name $SERVICE_NAME -ErrorAction SilentlyContinue
    if (!$service) {
        Write-Error "Service not installed"
        Write-Info "Install service first with: .\RiskNoXServiceControl.ps1 install"
        Write-Log "Protect failed: Service not installed" "ERROR"
        return $false
    }
    
    # Check if already protected
    $isProtected = Test-ServiceProtection -ServiceName $SERVICE_NAME
    if ($isProtected) {
        Write-Success "Service is already protected"
        Write-Log "Service already protected" "INFO"
        return $true
    }
    
    Write-Info "Applying service protection..."
    Write-Host ""
    
    try {
        # Set LocalSystem account
        Write-Info "Setting LocalSystem account..."
        sc.exe config $SERVICE_NAME obj= LocalSystem 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Write-Success "Service configured to run as LocalSystem"
        }
        
        # Apply SDDL protection
        Write-Info "Applying SDDL protection..."
        $sddl = "D:(D;;WPDT;;;BA)(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)"
        sc.exe sdset $SERVICE_NAME $sddl 2>&1 | Out-Null
        
        if ($LASTEXITCODE -eq 0) {
            Write-Success "SDDL protection applied"
        }
        else {
            Write-Error "Failed to apply SDDL protection"
            Write-Log "SDDL protection failed" "ERROR"
            return $false
        }
        
        # Configure auto-restart
        Write-Info "Configuring auto-restart on failure..."
        sc.exe failure $SERVICE_NAME reset= 0 actions= restart/0/restart/0/restart/0 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Write-Success "Auto-restart configured"
        }
        
        Write-Host ""
        Write-Success "Service protection applied successfully"
        Write-Log "Service protection applied" "SUCCESS"
        
        Write-Host ""
        Write-Warning "Important: Administrators cannot stop this service through Windows"
        Write-Info "Use this script to manage the service: .\RiskNoXServiceControl.ps1 stop"
        Write-Host ""
        
        return $true
    }
    catch {
        Write-Error "Failed to apply protection: $($_.Exception.Message)"
        Write-Log "Service protection failed: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

# Unprotect command - Remove service protection
function Invoke-Unprotect {
    Write-Header "REMOVING Service Protection"
    
    if (!(Test-Administrator)) {
        Write-Error "Administrator privileges required"
        Write-Info "Please run: Start-Process powershell -Verb RunAs -ArgumentList '-File ""$PSCommandPath"" unprotect'"
        Write-Log "Unprotect failed: Not running as administrator" "ERROR"
        return $false
    }
    
    Write-Log "Removing service protection" "INFO"
    
    $service = Get-Service -Name $SERVICE_NAME -ErrorAction SilentlyContinue
    if (!$service) {
        Write-Error "Service not installed"
        Write-Log "Unprotect failed: Service not installed" "ERROR"
        return $false
    }
    
    # Check if already unprotected
    $isProtected = Test-ServiceProtection -ServiceName $SERVICE_NAME
    if (!$isProtected) {
        Write-Success "Service is already unprotected"
        Write-Log "Service already unprotected" "INFO"
        return $true
    }
    
    Write-Info "Removing service protection..."
    Write-Host ""
    
    try {
        # Apply standard SDDL
        Write-Info "Restoring standard permissions..."
        $standardSDDL = "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)"
        sc.exe sdset $SERVICE_NAME $standardSDDL 2>&1 | Out-Null
        
        if ($LASTEXITCODE -eq 0) {
            Write-Success "Standard permissions restored"
        }
        else {
            Write-Error "Failed to restore permissions"
            Write-Log "SDDL restoration failed" "ERROR"
            return $false
        }
        
        Write-Host ""
        Write-Success "Service protection removed successfully"
        Write-Log "Service protection removed" "SUCCESS"
        
        Write-Host ""
        Write-Info "Administrators can now stop the service through Windows"
        Write-Info "To reapply protection, use: .\RiskNoXServiceControl.ps1 protect"
        Write-Host ""
        
        return $true
    }
    catch {
        Write-Error "Failed to remove protection: $($_.Exception.Message)"
        Write-Log "Service unprotection failed: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

# Help command
function Show-Help {
    Show-Banner
    
    Write-Host "USAGE:" -ForegroundColor Cyan
    Write-Host "  .\RiskNoXServiceControl.ps1 <command>" -ForegroundColor White
    Write-Host ""
    
    Write-Host "COMMANDS:" -ForegroundColor Cyan
    Write-Host "  install       Install service (dependencies, build, configure)" -ForegroundColor White
    Write-Host "  configure     Configure agent enrollment (redirects to UnifiedAgentControl.ps1)" -ForegroundColor White
    Write-Host "  start         Start service and verify all processes" -ForegroundColor White
    Write-Host "  stop          Stop service (requires admin privileges)" -ForegroundColor White
    Write-Host "  status        Show detailed status of service and processes" -ForegroundColor White
    Write-Host "  restart       Restart the service" -ForegroundColor White
    Write-Host "  protect       Apply LocalSystem + SDDL protection" -ForegroundColor White
    Write-Host "  unprotect     Remove service protection" -ForegroundColor White
    Write-Host "  uninstall     Remove service completely" -ForegroundColor White
    Write-Host "  help          Show this help message" -ForegroundColor White
    Write-Host ""
    
    Write-Host "EXAMPLES:" -ForegroundColor Cyan
    Write-Host "  .\RiskNoXServiceControl.ps1 install" -ForegroundColor Gray
    Write-Host "  .\RiskNoXServiceControl.ps1 configure" -ForegroundColor Gray
    Write-Host "  .\RiskNoXServiceControl.ps1 start" -ForegroundColor Gray
    Write-Host "  .\RiskNoXServiceControl.ps1 status" -ForegroundColor Gray
    Write-Host ""
    
    Write-Host "NOTES:" -ForegroundColor Cyan
    Write-Host "  • Service runs automatically on system boot" -ForegroundColor White
    Write-Host "  • Processes restart automatically on crash" -ForegroundColor White
    Write-Host "  • Service is protected by default (LocalSystem + SDDL)" -ForegroundColor White
    Write-Host "  • Only this script can stop the protected service" -ForegroundColor White
    Write-Host "  • Manages: monitoring_agent, suricata" -ForegroundColor White
    Write-Host ""
    
    Write-Host "PROTECTION:" -ForegroundColor Cyan
    Write-Host "  • Applied automatically during installation" -ForegroundColor White
    Write-Host "  • Prevents administrators from stopping via Windows" -ForegroundColor White
    Write-Host "  • Service runs as LocalSystem (highest privileges)" -ForegroundColor White
    Write-Host "  • Use 'protect' or 'unprotect' to manually manage" -ForegroundColor White
    Write-Host ""
}

# Main execution
try {
    Show-Banner
    
    switch ($Command.ToLower()) {
        "install"   { $result = Invoke-Install; exit ($result ? 0 : 1) }
        "configure" { $result = Invoke-Configure; exit ($result ? 0 : 1) }
        "start"     { $result = Invoke-Start; exit ($result ? 0 : 1) }
        "stop"      { $result = Invoke-Stop; exit ($result ? 0 : 1) }
        "status"    { $result = Invoke-Status; exit ($result ? 0 : 1) }
        "restart"   { $result = Invoke-Restart; exit ($result ? 0 : 1) }
        "protect"   { $result = Invoke-Protect; exit ($result ? 0 : 1) }
        "unprotect" { $result = Invoke-Unprotect; exit ($result ? 0 : 1) }
        "uninstall" { $result = Invoke-Uninstall; exit ($result ? 0 : 1) }
        "help"      { Show-Help; exit 0 }
        default     { Show-Help; exit 1 }
    }
}
catch {
    Write-Host ""
    Write-Error "FATAL ERROR: $($_.Exception.Message)"
    Write-Host "Stack Trace: $($_.ScriptStackTrace)" -ForegroundColor Red
    Write-Log "Fatal error: $($_.Exception.Message)" "ERROR"
    exit 1
}
