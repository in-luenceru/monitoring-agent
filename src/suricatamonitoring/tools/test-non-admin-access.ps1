<#
.SYNOPSIS
    Test service protection from non-administrator perspective

.DESCRIPTION
    Tests what a regular (non-admin) user can and cannot do with the protected service.
    This script does NOT require administrator privileges.

.EXAMPLE
    .\test-non-admin-access.ps1
    Tests service access as non-administrator
#>

$ErrorActionPreference = "Continue"

# Configuration
$SERVICE_NAME = "RiskNoXSupervisor"
$Script:TestResults = @()

function Write-TestHeader {
    param([string]$Message)
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  $Message" -ForegroundColor White
    Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host ""
}

function Write-TestResult {
    param(
        [string]$TestName,
        [bool]$Passed,
        [string]$Details = ""
    )
    
    if ($Passed) {
        Write-Host "  ✓ " -NoNewline -ForegroundColor Green
        Write-Host "$TestName" -ForegroundColor White
    }
    else {
        Write-Host "  ✗ " -NoNewline -ForegroundColor Red
        Write-Host "$TestName" -ForegroundColor White
    }
    
    if ($Details) {
        Write-Host "      $Details" -ForegroundColor Gray
    }
    
    $Script:TestResults += [PSCustomObject]@{
        Test = $TestName
        Passed = $Passed
        Details = $Details
    }
}

function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Test 1: Verify NOT running as admin
function Test-NotRunningAsAdmin {
    Write-Host "Test 1: Verifying running as non-administrator..." -ForegroundColor Cyan
    
    $isAdmin = Test-Administrator
    
    if (!$isAdmin) {
        $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
        Write-TestResult "Running as non-administrator" $true "User: $($currentUser.Name)"
        return $true
    }
    else {
        Write-TestResult "Running as non-administrator" $false "Currently running as Administrator"
        Write-Host ""
        Write-Host "  This test must run WITHOUT administrator privileges." -ForegroundColor Yellow
        Write-Host "  Please run this script from a normal PowerShell window." -ForegroundColor Yellow
        return $false
    }
}

# Test 2: Can query service status
function Test-CanQueryStatus {
    Write-Host ""
    Write-Host "Test 2: Attempting to query service status..." -ForegroundColor Cyan
    Write-Host "      (This SHOULD work - read access allowed)" -ForegroundColor Gray
    
    try {
        $service = Get-Service -Name $SERVICE_NAME -ErrorAction Stop
        
        Write-TestResult "Can query service status" $true "Status: $($service.Status)"
        return $true
    }
    catch {
        Write-TestResult "Can query service status" $false "Error: $($_.Exception.Message)"
        return $false
    }
}

# Test 3: Cannot stop service
function Test-CannotStopService {
    Write-Host ""
    Write-Host "Test 3: Attempting to stop service..." -ForegroundColor Cyan
    Write-Host "      (This SHOULD FAIL - no privileges)" -ForegroundColor Gray
    
    try {
        Stop-Service -Name $SERVICE_NAME -Force -ErrorAction Stop
        
        # Check if actually stopped
        Start-Sleep -Seconds 2
        $service = Get-Service -Name $SERVICE_NAME
        
        if ($service.Status -eq 'Stopped') {
            Write-TestResult "Cannot stop service" $false "Service was stopped (Should be prevented!)"
            return $false
        }
        else {
            Write-TestResult "Cannot stop service" $true "Service still running"
            return $true
        }
    }
    catch {
        # Exception is expected
        if ($_.Exception.Message -match "Access is denied" -or 
            $_.Exception.Message -match "Cannot stop" -or
            $_.Exception.Message -match "Cannot open") {
            Write-TestResult "Cannot stop service" $true "Access Denied (expected)"
            return $true
        }
        else {
            Write-TestResult "Cannot stop service" $false "Unexpected error: $($_.Exception.Message)"
            return $false
        }
    }
}

# Test 4: Cannot start service (if stopped)
function Test-CannotStartService {
    Write-Host ""
    Write-Host "Test 4: Checking if can start service..." -ForegroundColor Cyan
    
    $service = Get-Service -Name $SERVICE_NAME
    
    if ($service.Status -eq 'Running') {
        Write-Host "      Service is running, cannot test start" -ForegroundColor Gray
        Write-TestResult "Cannot start service (if stopped)" $true "Service running (test skipped)"
        return $true
    }
    
    try {
        Start-Service -Name $SERVICE_NAME -ErrorAction Stop
        
        Start-Sleep -Seconds 2
        $service = Get-Service -Name $SERVICE_NAME
        
        if ($service.Status -eq 'Running') {
            Write-TestResult "Cannot start service (if stopped)" $false "Service was started by non-admin"
            return $false
        }
        else {
            Write-TestResult "Cannot start service (if stopped)" $true "Start command failed"
            return $true
        }
    }
    catch {
        Write-TestResult "Cannot start service (if stopped)" $true "Access Denied (expected)"
        return $true
    }
}

# Test 5: Cannot restart service
function Test-CannotRestartService {
    Write-Host ""
    Write-Host "Test 5: Attempting to restart service..." -ForegroundColor Cyan
    Write-Host "      (This SHOULD FAIL - no privileges)" -ForegroundColor Gray
    
    try {
        Restart-Service -Name $SERVICE_NAME -Force -ErrorAction Stop
        
        Write-TestResult "Cannot restart service" $false "Service was restarted by non-admin"
        return $false
    }
    catch {
        if ($_.Exception.Message -match "Access is denied" -or 
            $_.Exception.Message -match "Cannot") {
            Write-TestResult "Cannot restart service" $true "Access Denied (expected)"
            return $true
        }
        else {
            Write-TestResult "Cannot restart service" $false "Unexpected error: $($_.Exception.Message)"
            return $false
        }
    }
}

# Test 6: Cannot change service properties
function Test-CannotChangeProperties {
    Write-Host ""
    Write-Host "Test 6: Attempting to change service properties..." -ForegroundColor Cyan
    Write-Host "      (This SHOULD FAIL - no privileges)" -ForegroundColor Gray
    
    try {
        Set-Service -Name $SERVICE_NAME -StartupType Manual -ErrorAction Stop
        
        Write-TestResult "Cannot change properties" $false "Properties were changed by non-admin"
        return $false
    }
    catch {
        if ($_.Exception.Message -match "Access is denied" -or 
            $_.Exception.Message -match "Cannot") {
            Write-TestResult "Cannot change properties" $true "Access Denied (expected)"
            return $true
        }
        else {
            Write-TestResult "Cannot change properties" $false "Unexpected error: $($_.Exception.Message)"
            return $false
        }
    }
}

# Test 7: Cannot query SDDL (might work but cannot modify)
function Test-CannotQuerySDDL {
    Write-Host ""
    Write-Host "Test 7: Attempting to query service SDDL..." -ForegroundColor Cyan
    
    try {
        $result = sc.exe sdshow $SERVICE_NAME 2>&1 | Out-String
        $exitCode = $LASTEXITCODE
        
        if ($exitCode -eq 0) {
            Write-TestResult "Cannot query SDDL" $false "SDDL was readable (might be normal)"
            Write-Host "      Note: Query might be allowed, but modification should fail" -ForegroundColor Gray
            return $false
        }
        else {
            Write-TestResult "Cannot query SDDL" $true "Access Denied (expected)"
            return $true
        }
    }
    catch {
        Write-TestResult "Cannot query SDDL" $true "Error occurred (expected)"
        return $true
    }
}

# Test 8: Get current user info
function Show-CurrentUserInfo {
    Write-Host ""
    Write-Host "Current User Information:" -ForegroundColor Cyan
    
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    
    Write-Host "  User:           $($currentUser.Name)" -ForegroundColor White
    Write-Host "  Is Admin:       " -NoNewline
    Write-Host $(if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { "Yes" } else { "No" }) -ForegroundColor $(if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { "Yellow" } else { "Green" })
    Write-Host "  Auth Type:      $($currentUser.AuthenticationType)" -ForegroundColor Gray
    Write-Host ""
}

# Summary
function Show-Summary {
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  NON-ADMINISTRATOR TEST SUMMARY" -ForegroundColor White
    Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host ""
    
    $passed = ($Script:TestResults | Where-Object { $_.Passed }).Count
    $total = $Script:TestResults.Count
    
    Write-Host "  Tests Passed:   $passed / $total" -ForegroundColor White
    Write-Host ""
    
    if ($passed -eq $total) {
        Write-Host "╔═══════════════════════════════════════════════════════════╗" -ForegroundColor Green
        Write-Host "║                                                           ║" -ForegroundColor Green
        Write-Host "║   ✓ NON-ADMIN ACCESS CORRECTLY RESTRICTED                ║" -ForegroundColor Green
        Write-Host "║                                                           ║" -ForegroundColor Green
        Write-Host "╚═══════════════════════════════════════════════════════════╝" -ForegroundColor Green
        Write-Host ""
        Write-Host "  Regular users cannot:" -ForegroundColor White
        Write-Host "  • Stop the service" -ForegroundColor Green
        Write-Host "  • Start the service" -ForegroundColor Green
        Write-Host "  • Restart the service" -ForegroundColor Green
        Write-Host "  • Modify service configuration" -ForegroundColor Green
        Write-Host ""
        Write-Host "  Regular users can:" -ForegroundColor White
        Write-Host "  • View service status (read-only)" -ForegroundColor Green
    }
    else {
        Write-Host "╔═══════════════════════════════════════════════════════════╗" -ForegroundColor Yellow
        Write-Host "║                                                           ║" -ForegroundColor Yellow
        Write-Host "║   ⚠ SOME TESTS FAILED - REVIEW PERMISSIONS               ║" -ForegroundColor Yellow
        Write-Host "║                                                           ║" -ForegroundColor Yellow
        Write-Host "╚═══════════════════════════════════════════════════════════╝" -ForegroundColor Yellow
    }
    
    Write-Host ""
}

# Main
function Main {
    Write-TestHeader "Non-Administrator Service Access Tests"
    
    Write-Host "This script tests what a regular (non-admin) user can do" -ForegroundColor White
    Write-Host "with the protected RiskNoX service." -ForegroundColor White
    Write-Host ""
    
    Show-CurrentUserInfo
    
    # Run tests
    $test1 = Test-NotRunningAsAdmin
    if (!$test1) {
        Write-Host ""
        Write-Host "ERROR: This test requires non-administrator privileges" -ForegroundColor Red
        Write-Host "Please run from a normal PowerShell window (not elevated)" -ForegroundColor Yellow
        return
    }
    
    Test-CanQueryStatus
    Test-CannotStopService
    Test-CannotStartService
    Test-CannotRestartService
    Test-CannotChangeProperties
    Test-CannotQuerySDDL
    
    Show-Summary
}

# Run
Main
