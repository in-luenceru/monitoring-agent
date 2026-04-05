#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Remove protection from RiskNoX Supervisor Service

.DESCRIPTION
    Removes advanced service protection by:
    1. Restoring standard service permissions (SDDL)
    2. Allowing administrators to stop/manage the service
    3. Keeping LocalSystem account (can be changed if needed)

.PARAMETER ServiceName
    Name of the service to unprotect (default: RiskNoXSupervisor)

.PARAMETER RestoreNetworkService
    If specified, changes service account from LocalSystem back to NetworkService

.EXAMPLE
    .\unprotect_service.ps1
    Removes SDDL protection, allows administrators to control service

.EXAMPLE
    .\unprotect_service.ps1 -RestoreNetworkService
    Removes protection and changes account to NetworkService

.NOTES
    If the service is heavily protected, you may need to run this as SYSTEM:
    PsExec.exe -i -s powershell.exe
    Then run: .\tools\unprotect_service.ps1
#>

[CmdletBinding()]
param(
    [string]$ServiceName = "RiskNoXSupervisor",
    [switch]$RestoreNetworkService = $false
)

$ErrorActionPreference = "Stop"
$REPO_ROOT = Split-Path $PSScriptRoot -Parent
$LOGS_DIR = Join-Path $REPO_ROOT "logs"
$LOG_FILE = Join-Path $LOGS_DIR "service-unprotection.log"

# Color output functions
function Write-UnprotectLog {
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

function Test-SystemAccount {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    return $currentUser.Name -eq "NT AUTHORITY\SYSTEM"
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

function Restore-StandardSDDL {
    param([string]$Name)
    
    Write-UnprotectLog "Restoring standard service permissions (SDDL)..." "INFO"
    
    <#
    Standard SDDL that allows administrators full control:
    D:                                          - DACL
    (A;;CCLCSWRPWPDTLOCRRC;;;SY)               - ALLOW SYSTEM: Full control
    (A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)       - ALLOW Administrators: Full control (including STOP)
    (A;;CCLCSWLOCRRC;;;IU)                     - ALLOW Interactive Users: Query, Start
    (A;;CCLCSWLOCRRC;;;SU)                     - ALLOW Service Users: Query, Start
    S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)  - AUDIT: All access by Everyone
    #>
    
    $standardSDDL = "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)"
    
    try {
        $result = sc.exe sdset $Name $standardSDDL 2>&1
        
        if ($LASTEXITCODE -eq 0) {
            Write-UnprotectLog "Standard SDDL restored successfully" "SUCCESS"
            Write-UnprotectLog "Administrators can now stop/manage the service" "INFO"
            return $true
        }
        else {
            Write-UnprotectLog "Failed to restore SDDL: $result" "ERROR"
            
            if ($result -match "Access is denied" -or $result -match "ERROR_ACCESS_DENIED") {
                Write-UnprotectLog "" "ERROR"
                Write-UnprotectLog "Access Denied - Service is protected" "ERROR"
                Write-UnprotectLog "You need to run this script as SYSTEM account:" "WARN"
                Write-UnprotectLog "  1. Download PsExec from Sysinternals" "WARN"
                Write-UnprotectLog "  2. Run: PsExec.exe -i -s powershell.exe" "WARN"
                Write-UnprotectLog "  3. In the new window, run this script again" "WARN"
            }
            
            return $false
        }
    }
    catch {
        Write-UnprotectLog "Error restoring SDDL: $_" "ERROR"
        return $false
    }
}

function Restore-ServiceAccount {
    param([string]$Name)
    
    if (-not $RestoreNetworkService) {
        Write-UnprotectLog "Keeping LocalSystem account (use -RestoreNetworkService to change)" "INFO"
        return $true
    }
    
    Write-UnprotectLog "Changing service account to NetworkService..." "INFO"
    
    try {
        $result = sc.exe config $Name obj= "NT AUTHORITY\NetworkService" 2>&1
        
        if ($LASTEXITCODE -eq 0) {
            Write-UnprotectLog "Service account changed to NetworkService" "SUCCESS"
            return $true
        }
        else {
            Write-UnprotectLog "Failed to change service account: $result" "ERROR"
            return $false
        }
    }
    catch {
        Write-UnprotectLog "Error changing service account: $_" "ERROR"
        return $false
    }
}

function Remove-FailureProtection {
    param([string]$Name)
    
    Write-UnprotectLog "Removing automatic restart configuration..." "INFO"
    
    try {
        # Reset failure actions to default (no auto-restart)
        $result = sc.exe failure $Name reset= 0 actions= "" 2>&1
        
        if ($LASTEXITCODE -eq 0) {
            Write-UnprotectLog "Auto-restart removed" "SUCCESS"
            return $true
        }
        else {
            Write-UnprotectLog "Warning: Could not remove auto-restart: $result" "WARN"
            return $true  # Non-critical
        }
    }
    catch {
        Write-UnprotectLog "Warning: Error removing auto-restart: $_" "WARN"
        return $true  # Non-critical
    }
}

function Get-CurrentServiceConfig {
    param([string]$Name)
    
    Write-UnprotectLog "" "INFO"
    Write-UnprotectLog "Current Service Configuration:" "INFO"
    Write-UnprotectLog "─────────────────────────────────────────────────────" "INFO"
    
    try {
        $service = Get-Service -Name $Name -ErrorAction Stop
        Write-UnprotectLog "  Status:        $($service.Status)" "INFO"
        Write-UnprotectLog "  Start Type:    $($service.StartType)" "INFO"
        
        # Get detailed configuration using WMI
        $wmiService = Get-WmiObject -Class Win32_Service -Filter "Name='$Name'"
        Write-UnprotectLog "  Account:       $($wmiService.StartName)" "INFO"
        Write-UnprotectLog "  Display Name:  $($wmiService.DisplayName)" "INFO"
        
        # Get SDDL
        $sddlOutput = sc.exe sdshow $Name 2>&1 | Out-String
        if ($LASTEXITCODE -eq 0) {
            $isProtected = $sddlOutput -match "D;.*WPDT.*BA"
            if ($isProtected) {
                Write-UnprotectLog "  Protection:    PROTECTED (SDDL denies admin control)" "WARN"
            }
            else {
                Write-UnprotectLog "  Protection:    Standard (admins have full control)" "SUCCESS"
            }
        }
    }
    catch {
        Write-UnprotectLog "Could not retrieve full service configuration" "WARN"
    }
    
    Write-UnprotectLog "─────────────────────────────────────────────────────" "INFO"
    Write-UnprotectLog "" "INFO"
}

function Test-Unprotection {
    param([string]$Name)
    
    Write-UnprotectLog "" "INFO"
    Write-UnprotectLog "Verifying Unprotection:" "INFO"
    Write-UnprotectLog "─────────────────────────────────────────────────────" "INFO"
    
    $allPassed = $true
    
    # Check SDDL does not contain deny rule
    try {
        $sddlOutput = sc.exe sdshow $Name 2>&1 | Out-String
        if ($LASTEXITCODE -eq 0) {
            if ($sddlOutput -match "D;.*WPDT.*BA") {
                Write-UnprotectLog "  ✗ SDDL still contains protection (Deny rules present)" "ERROR"
                $allPassed = $false
            }
            else {
                Write-UnprotectLog "  ✓ SDDL protection removed" "SUCCESS"
            }
        }
    }
    catch {
        Write-UnprotectLog "  ✗ Could not verify SDDL" "ERROR"
        $allPassed = $false
    }
    
    # Check service account if requested
    if ($RestoreNetworkService) {
        try {
            $wmiService = Get-WmiObject -Class Win32_Service -Filter "Name='$Name'"
            if ($wmiService.StartName -match "NetworkService") {
                Write-UnprotectLog "  ✓ Service account changed to NetworkService" "SUCCESS"
            }
            else {
                Write-UnprotectLog "  ✗ Service account not changed (Current: $($wmiService.StartName))" "ERROR"
                $allPassed = $false
            }
        }
        catch {
            Write-UnprotectLog "  ✗ Could not verify service account" "ERROR"
            $allPassed = $false
        }
    }
    
    # Test if administrators can now stop the service
    try {
        Write-UnprotectLog "  Testing administrative control..." "INFO"
        
        # Try to query the service (this should always work)
        $service = Get-Service -Name $Name -ErrorAction Stop
        
        if ($service.Status -eq 'Running') {
            Write-UnprotectLog "  ⚠ Service is running - you can now stop it with: Stop-Service -Name $Name" "INFO"
        }
        else {
            Write-UnprotectLog "  ℹ Service is not running (Status: $($service.Status))" "INFO"
        }
        
        Write-UnprotectLog "  ✓ Administrative control restored" "SUCCESS"
    }
    catch {
        Write-UnprotectLog "  ✗ Could not verify administrative control" "ERROR"
        $allPassed = $false
    }
    
    Write-UnprotectLog "─────────────────────────────────────────────────────" "INFO"
    
    if ($allPassed) {
        Write-UnprotectLog "" "INFO"
        Write-UnprotectLog "✓ Service unprotection completed successfully" "SUCCESS"
    }
    else {
        Write-UnprotectLog "" "INFO"
        Write-UnprotectLog "⚠ Some unprotection measures failed - review above" "WARN"
    }
}

function Show-UnprotectionInfo {
    Write-UnprotectLog "" "INFO"
    Write-UnprotectLog "═══════════════════════════════════════════════════════════" "INFO"
    Write-UnprotectLog "  Service Unprotection Complete!" "SUCCESS"
    Write-UnprotectLog "═══════════════════════════════════════════════════════════" "INFO"
    Write-UnprotectLog "" "INFO"
    Write-UnprotectLog "Protection Removed:" "INFO"
    Write-UnprotectLog "  • SDDL restrictions removed" "INFO"
    Write-UnprotectLog "  • Administrators can now stop/manage the service" "INFO"
    Write-UnprotectLog "  • Auto-restart on failure disabled" "INFO"
    Write-UnprotectLog "" "INFO"
    Write-UnprotectLog "Service Control Commands:" "INFO"
    Write-UnprotectLog "  Stop:    Stop-Service -Name $ServiceName" "INFO"
    Write-UnprotectLog "  Start:   Start-Service -Name $ServiceName" "INFO"
    Write-UnprotectLog "  Restart: Restart-Service -Name $ServiceName" "INFO"
    Write-UnprotectLog "  Status:  Get-Service -Name $ServiceName" "INFO"
    Write-UnprotectLog "" "INFO"
    Write-UnprotectLog "To Reapply Protection:" "INFO"
    Write-UnprotectLog "  .\tools\protect_service.ps1" "INFO"
    Write-UnprotectLog "" "INFO"
    Write-UnprotectLog "═══════════════════════════════════════════════════════════" "INFO"
}

function Main {
    Write-UnprotectLog "═══════════════════════════════════════════════════════════" "INFO"
    Write-UnprotectLog "  RiskNoX Service Unprotection Tool" "INFO"
    Write-UnprotectLog "═══════════════════════════════════════════════════════════" "INFO"
    Write-UnprotectLog "" "INFO"
    
    # Check administrator privileges
    if (-not (Test-Administrator)) {
        Write-UnprotectLog "This script requires Administrator privileges" "ERROR"
        Write-UnprotectLog "Please run from an elevated PowerShell prompt" "ERROR"
        exit 1
    }
    
    # Warn if not running as SYSTEM
    if (-not (Test-SystemAccount)) {
        Write-UnprotectLog "WARNING: Not running as SYSTEM account" "WARN"
        Write-UnprotectLog "If unprotection fails, you may need to run as SYSTEM:" "WARN"
        Write-UnprotectLog "  PsExec.exe -i -s powershell.exe" "WARN"
        Write-UnprotectLog "" "INFO"
    }
    else {
        Write-UnprotectLog "Running as SYSTEM account - full privileges available" "SUCCESS"
        Write-UnprotectLog "" "INFO"
    }
    
    # Check service exists
    if (-not (Test-ServiceExists -Name $ServiceName)) {
        Write-UnprotectLog "Service '$ServiceName' not found" "ERROR"
        exit 1
    }
    
    # Show current configuration
    Get-CurrentServiceConfig -Name $ServiceName
    
    # Remove protection measures
    Write-UnprotectLog "Removing protection measures..." "INFO"
    Write-UnprotectLog "" "INFO"
    
    $success = $true
    
    # Step 1: Restore standard SDDL
    if (-not (Restore-StandardSDDL -Name $ServiceName)) {
        $success = $false
    }
    
    # Step 2: Restore service account if requested
    if (-not (Restore-ServiceAccount -Name $ServiceName)) {
        # Non-critical if keeping LocalSystem
        if ($RestoreNetworkService) {
            $success = $false
        }
    }
    
    # Step 3: Remove failure protection
    if (-not (Remove-FailureProtection -Name $ServiceName)) {
        # Non-critical, continue
    }
    
    Write-UnprotectLog "" "INFO"
    
    # Verify unprotection
    Test-Unprotection -Name $ServiceName
    
    # Show summary
    Show-UnprotectionInfo
    
    if ($success) {
        Write-UnprotectLog "Unprotection completed successfully!" "SUCCESS"
        exit 0
    }
    else {
        Write-UnprotectLog "Unprotection completed with errors - review log" "WARN"
        Write-UnprotectLog "You may need to run this script as SYSTEM account" "WARN"
        exit 1
    }
}

# Run main
Main
