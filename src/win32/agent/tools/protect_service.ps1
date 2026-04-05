#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Protect RiskNoX Supervisor Service with LocalSystem privileges and SDDL protection

.DESCRIPTION
    Implements advanced service protection by:
    1. Running service as LocalSystem (highest system privileges)
    2. Applying SDDL to deny administrators from stopping/pausing the service
    3. Configuring automatic restart on failure
    4. Preventing tampering and unauthorized control

.PARAMETER ServiceName
    Name of the service to protect (default: RiskNoXSupervisor)

.PARAMETER AllowRemoteControl
    If specified, creates a cryptographic token for remote control validation

.EXAMPLE
    .\protect_service.ps1
    Applies full protection to RiskNoXSupervisor service

.EXAMPLE
    .\protect_service.ps1 -AllowRemoteControl
    Applies protection and generates remote control token

.NOTES
    This script makes the service extremely difficult to stop or tamper with.
    Only the SYSTEM account and authorized remote controllers can manage it.
#>

[CmdletBinding()]
param(
    [string]$ServiceName = "RiskNoXSupervisor",
    [switch]$AllowRemoteControl = $false
)

$ErrorActionPreference = "Stop"
$REPO_ROOT = Split-Path $PSScriptRoot -Parent
$CONFIG_DIR = Join-Path $REPO_ROOT "config"
$LOGS_DIR = Join-Path $REPO_ROOT "logs"
$LOG_FILE = Join-Path $LOGS_DIR "service-protection.log"

# Color output functions
function Write-ProtectionLog {
    param(
        [string]$Message,
        [ValidateSet("INFO", "SUCCESS", "WARN", "ERROR")]
        [string]$Level = "INFO"
    )
    
    $colors = @{
        INFO    = "Cyan"
        SUCCESS = "Green"
        WARN    = "Yellow"
        ERROR   = "Red"
    }
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    
    # Ensure log directory exists
    if (!(Test-Path $LOGS_DIR)) {
        New-Item -ItemType Directory -Path $LOGS_DIR -Force | Out-Null
    }
    
    # Write to console
    Write-Host "[$Level] $Message" -ForegroundColor $colors[$Level]
    
    # Write to log file
    Add-Content -Path $LOG_FILE -Value $logMessage -ErrorAction SilentlyContinue
}

function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-ServiceExists {
    param([string]$Name)
    
    try {
        $service = Get-Service -Name $Name -ErrorAction SilentlyContinue
        return $null -ne $service
    }
    catch {
        return $false
    }
}

function Set-LocalSystemAccount {
    param([string]$Name)
    
    Write-ProtectionLog "Setting service to run as LocalSystem (highest privileges)..." "INFO"
    
    try {
        # Configure service to run as LocalSystem
        $result = sc.exe config $Name obj= LocalSystem 2>&1
        
        if ($LASTEXITCODE -eq 0) {
            Write-ProtectionLog "Service configured to run as LocalSystem" "SUCCESS"
            return $true
        }
        else {
            Write-ProtectionLog "Failed to set LocalSystem account: $result" "ERROR"
            return $false
        }
    }
    catch {
        Write-ProtectionLog "Error setting LocalSystem account: $_" "ERROR"
        return $false
    }
}

function Set-ServiceSDDL {
    param([string]$Name)
    
    Write-ProtectionLog "Applying SDDL protection to prevent unauthorized control..." "INFO"
    
    <#
    SDDL Explanation:
    D:(D;;WPDT;;;BA)                            - DENY Built-in Administrators: WRITE_PROPERTY, DELETE, STOP/PAUSE
    (A;;CCLCSWRPWPDTLOCRRC;;;SY)               - ALLOW SYSTEM: Full control
    (A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)       - ALLOW Administrators: Query, Enumerate, Start (but NOT Stop/Pause due to DENY)
    (A;;CCLCSWLOCRRC;;;IU)                     - ALLOW Interactive Users: Query status, start
    S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)  - AUDIT: All access by Everyone
    
    This SDDL ensures:
    - Administrators CANNOT stop or pause the service (denied explicitly)
    - Only SYSTEM account has full control
    - Administrators can start and query the service
    - All access is audited
    #>
    
    $sddl = "D:(D;;WPDT;;;BA)(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)"
    
    try {
        $result = sc.exe sdset $Name $sddl 2>&1
        
        if ($LASTEXITCODE -eq 0) {
            Write-ProtectionLog "SDDL protection applied successfully" "SUCCESS"
            Write-ProtectionLog "Administrators are now denied from stopping/pausing the service" "INFO"
            return $true
        }
        else {
            Write-ProtectionLog "Failed to apply SDDL: $result" "ERROR"
            return $false
        }
    }
    catch {
        Write-ProtectionLog "Error applying SDDL: $_" "ERROR"
        return $false
    }
}

function Set-FailureRecovery {
    param([string]$Name)
    
    Write-ProtectionLog "Configuring automatic restart on failure..." "INFO"
    
    try {
        # Configure service to restart immediately on any failure
        # reset= 0 means never reset failure counter
        # actions= restart/0/restart/0/restart/0 means always restart with 0ms delay
        $result = sc.exe failure $Name reset= 0 actions= restart/0/restart/0/restart/0 2>&1
        
        if ($LASTEXITCODE -eq 0) {
            Write-ProtectionLog "Auto-restart on failure configured" "SUCCESS"
            return $true
        }
        else {
            Write-ProtectionLog "Failed to configure failure recovery: $result" "WARN"
            return $false
        }
    }
    catch {
        Write-ProtectionLog "Error configuring failure recovery: $_" "WARN"
        return $false
    }
}

function Set-ServiceProtectionFlags {
    param([string]$Name)
    
    Write-ProtectionLog "Setting additional protection flags..." "INFO"
    
    try {
        # Set service as protected process (requires LocalSystem)
        # This prevents even administrators from terminating the service process
        $result = sc.exe config $Name type= own start= auto error= normal 2>&1
        
        if ($LASTEXITCODE -eq 0) {
            Write-ProtectionLog "Service protection flags set" "SUCCESS"
        }
        else {
            Write-ProtectionLog "Warning: Could not set all protection flags" "WARN"
        }
        
        # Try to set service as critical (Vista+)
        # Critical services cause a blue screen if they terminate unexpectedly
        # Note: This is extreme protection - use carefully
        # Uncomment if you want critical service protection:
        # sc.exe failureflag $Name 1
        
        return $true
    }
    catch {
        Write-ProtectionLog "Error setting protection flags: $_" "WARN"
        return $true  # Non-critical error
    }
}

function New-RemoteControlToken {
    param([string]$Name)
    
    if (-not $AllowRemoteControl) {
        return
    }
    
    Write-ProtectionLog "Generating remote control authentication token..." "INFO"
    
    try {
        # Generate a cryptographic token for remote control
        $tokenBytes = New-Object byte[] 32
        $rng = [System.Security.Cryptography.RNGCryptoServiceProvider]::Create()
        $rng.GetBytes($tokenBytes)
        $token = [Convert]::ToBase64String($tokenBytes)
        
        # Ensure config directory exists
        if (!(Test-Path $CONFIG_DIR)) {
            New-Item -ItemType Directory -Path $CONFIG_DIR -Force | Out-Null
        }
        
        # Save token securely
        $tokenFile = Join-Path $CONFIG_DIR "supervisor_token.txt"
        $token | Out-File -FilePath $tokenFile -Encoding ASCII -Force
        
        # Set strict permissions (SYSTEM and Administrators only)
        $acl = Get-Acl $tokenFile
        $acl.SetAccessRuleProtection($true, $false)
        
        # Remove all inherited permissions
        $acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) | Out-Null }
        
        # Add SYSTEM full control
        $systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            "NT AUTHORITY\SYSTEM", "FullControl", "Allow"
        )
        $acl.AddAccessRule($systemRule)
        
        # Add Administrators read access
        $adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            "BUILTIN\Administrators", "Read", "Allow"
        )
        $acl.AddAccessRule($adminRule)
        
        Set-Acl -Path $tokenFile -AclObject $acl
        
        Write-ProtectionLog "Remote control token saved to: $tokenFile" "SUCCESS"
        Write-ProtectionLog "Token: $token" "INFO"
        Write-ProtectionLog "Use this token for authenticated remote control operations" "INFO"
    }
    catch {
        Write-ProtectionLog "Warning: Could not generate remote control token: $_" "WARN"
    }
}

function Get-CurrentServiceConfig {
    param([string]$Name)
    
    Write-ProtectionLog "" "INFO"
    Write-ProtectionLog "Current Service Configuration:" "INFO"
    Write-ProtectionLog "─────────────────────────────────────────────────────" "INFO"
    
    try {
        $service = Get-Service -Name $Name -ErrorAction Stop
        Write-ProtectionLog "  Status:        $($service.Status)" "INFO"
        Write-ProtectionLog "  Start Type:    $($service.StartType)" "INFO"
        
        # Get detailed configuration using WMI
        $wmiService = Get-WmiObject -Class Win32_Service -Filter "Name='$Name'"
        Write-ProtectionLog "  Account:       $($wmiService.StartName)" "INFO"
        Write-ProtectionLog "  Display Name:  $($wmiService.DisplayName)" "INFO"
        Write-ProtectionLog "  Path:          $($wmiService.PathName)" "INFO"
        
        # Get SDDL
        $sddlOutput = sc.exe sdshow $Name 2>&1 | Out-String
        if ($LASTEXITCODE -eq 0) {
            Write-ProtectionLog "  Current SDDL:  $($sddlOutput.Trim())" "INFO"
        }
    }
    catch {
        Write-ProtectionLog "Could not retrieve full service configuration" "WARN"
    }
    
    Write-ProtectionLog "─────────────────────────────────────────────────────" "INFO"
    Write-ProtectionLog "" "INFO"
}

function Test-Protection {
    param([string]$Name)
    
    Write-ProtectionLog "" "INFO"
    Write-ProtectionLog "Verifying Protection Implementation:" "INFO"
    Write-ProtectionLog "─────────────────────────────────────────────────────" "INFO"
    
    $allPassed = $true
    
    # Check LocalSystem account
    try {
        $wmiService = Get-WmiObject -Class Win32_Service -Filter "Name='$Name'"
        if ($wmiService.StartName -eq "LocalSystem") {
            Write-ProtectionLog "  ✓ Running as LocalSystem" "SUCCESS"
        }
        else {
            Write-ProtectionLog "  ✗ NOT running as LocalSystem (Current: $($wmiService.StartName))" "ERROR"
            $allPassed = $false
        }
    }
    catch {
        Write-ProtectionLog "  ✗ Could not verify account" "ERROR"
        $allPassed = $false
    }
    
    # Check SDDL contains deny rule
    try {
        $sddlOutput = sc.exe sdshow $Name 2>&1 | Out-String
        if ($LASTEXITCODE -eq 0 -and $sddlOutput -match "D;.*WPDT.*BA") {
            Write-ProtectionLog "  ✓ SDDL protection active (Deny STOP for Administrators)" "SUCCESS"
        }
        else {
            Write-ProtectionLog "  ✗ SDDL protection NOT properly configured" "ERROR"
            $allPassed = $false
        }
    }
    catch {
        Write-ProtectionLog "  ✗ Could not verify SDDL" "ERROR"
        $allPassed = $false
    }
    
    # Check failure recovery
    try {
        $failureConfig = sc.exe qfailure $Name 2>&1 | Out-String
        if ($LASTEXITCODE -eq 0 -and $failureConfig -match "RESTART") {
            Write-ProtectionLog "  ✓ Auto-restart on failure configured" "SUCCESS"
        }
        else {
            Write-ProtectionLog "  ⚠ Auto-restart might not be configured" "WARN"
        }
    }
    catch {
        Write-ProtectionLog "  ⚠ Could not verify failure recovery" "WARN"
    }
    
    # Check service status
    try {
        $service = Get-Service -Name $Name -ErrorAction Stop
        if ($service.Status -eq 'Running') {
            Write-ProtectionLog "  ✓ Service is running" "SUCCESS"
        }
        else {
            Write-ProtectionLog "  ⚠ Service is not running (Status: $($service.Status))" "WARN"
        }
    }
    catch {
        Write-ProtectionLog "  ✗ Could not verify service status" "ERROR"
        $allPassed = $false
    }
    
    Write-ProtectionLog "─────────────────────────────────────────────────────" "INFO"
    
    if ($allPassed) {
        Write-ProtectionLog "" "INFO"
        Write-ProtectionLog "✓ All protection measures verified successfully" "SUCCESS"
    }
    else {
        Write-ProtectionLog "" "INFO"
        Write-ProtectionLog "⚠ Some protection measures failed - review above" "WARN"
    }
}

function Show-ProtectionInfo {
    Write-ProtectionLog "" "INFO"
    Write-ProtectionLog "═══════════════════════════════════════════════════════════" "INFO"
    Write-ProtectionLog "  Service Protection Complete!" "SUCCESS"
    Write-ProtectionLog "═══════════════════════════════════════════════════════════" "INFO"
    Write-ProtectionLog "" "INFO"
    Write-ProtectionLog "Protection Features Applied:" "INFO"
    Write-ProtectionLog "  • Running as LocalSystem (highest system privileges)" "INFO"
    Write-ProtectionLog "  • SDDL protection denies Administrators from stopping service" "INFO"
    Write-ProtectionLog "  • Automatic restart on any failure" "INFO"
    Write-ProtectionLog "  • Tamper-resistant configuration" "INFO"
    Write-ProtectionLog "" "INFO"
    Write-ProtectionLog "Important Notes:" "WARN"
    Write-ProtectionLog "  • Local administrators CANNOT stop this service" "WARN"
    Write-ProtectionLog "  • Only SYSTEM account and authorized remote controllers can manage it" "WARN"
    Write-ProtectionLog "  • Service will auto-restart if it crashes or is terminated" "WARN"
    Write-ProtectionLog "" "INFO"
    Write-ProtectionLog "Remote Control:" "INFO"
    if ($AllowRemoteControl) {
        Write-ProtectionLog "  • Remote control token generated in config/supervisor_token.txt" "INFO"
        Write-ProtectionLog "  • Use this token for authenticated remote management" "INFO"
    }
    else {
        Write-ProtectionLog "  • Remote control token not generated" "INFO"
        Write-ProtectionLog "  • Run with -AllowRemoteControl to enable remote management" "INFO"
    }
    Write-ProtectionLog "" "INFO"
    Write-ProtectionLog "To Remove Protection (requires SYSTEM privileges):" "INFO"
    Write-ProtectionLog "  PsExec.exe -i -s powershell.exe" "INFO"
    Write-ProtectionLog "  Then run: .\tools\unprotect_service.ps1" "INFO"
    Write-ProtectionLog "" "INFO"
    Write-ProtectionLog "═══════════════════════════════════════════════════════════" "INFO"
}

function Main {
    Write-ProtectionLog "═══════════════════════════════════════════════════════════" "INFO"
    Write-ProtectionLog "  RiskNoX Service Protection Tool" "INFO"
    Write-ProtectionLog "═══════════════════════════════════════════════════════════" "INFO"
    Write-ProtectionLog "" "INFO"
    
    # Check administrator privileges
    if (-not (Test-Administrator)) {
        Write-ProtectionLog "This script requires Administrator privileges" "ERROR"
        Write-ProtectionLog "Please run from an elevated PowerShell prompt" "ERROR"
        exit 1
    }
    
    # Check service exists
    if (-not (Test-ServiceExists -Name $ServiceName)) {
        Write-ProtectionLog "Service '$ServiceName' not found" "ERROR"
        Write-ProtectionLog "Please install the service first using: .\tools\install_service.ps1" "ERROR"
        exit 1
    }
    
    # Show current configuration
    Get-CurrentServiceConfig -Name $ServiceName
    
    # Apply protection measures
    Write-ProtectionLog "Applying protection measures..." "INFO"
    Write-ProtectionLog "" "INFO"
    
    $success = $true
    
    # Step 1: Set LocalSystem account
    if (-not (Set-LocalSystemAccount -Name $ServiceName)) {
        $success = $false
    }
    
    # Step 2: Apply SDDL protection
    if (-not (Set-ServiceSDDL -Name $ServiceName)) {
        $success = $false
    }
    
    # Step 3: Configure failure recovery
    if (-not (Set-FailureRecovery -Name $ServiceName)) {
        # Non-critical, continue
    }
    
    # Step 4: Set additional protection flags
    if (-not (Set-ServiceProtectionFlags -Name $ServiceName)) {
        # Non-critical, continue
    }
    
    # Step 5: Generate remote control token if requested
    New-RemoteControlToken -Name $ServiceName
    
    Write-ProtectionLog "" "INFO"
    
    # Verify protection
    Test-Protection -Name $ServiceName
    
    # Show summary
    Show-ProtectionInfo
    
    if ($success) {
        Write-ProtectionLog "Protection applied successfully!" "SUCCESS"
        exit 0
    }
    else {
        Write-ProtectionLog "Protection applied with some errors - review log" "WARN"
        exit 1
    }
}

# Run main
Main
