#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Test and verify RiskNoX service protection

.DESCRIPTION
    Comprehensive test suite to verify that:
    1. Service is running as LocalSystem
    2. SDDL protection is correctly applied
    3. Administrators CANNOT stop the service via Windows
    4. Administrators CANNOT modify service configuration
    5. Administrators CANNOT uninstall via Windows
    6. Only the RiskNoXServiceControl.ps1 script can manage the service
    7. Service auto-restarts on failure
    8. Regular users have no control

.EXAMPLE
    .\test-service-protection.ps1
    Runs all protection tests and displays results
#>

$ErrorActionPreference = "Continue"  # Continue on errors (expected for protected service)

# Configuration
$REPO_ROOT = Split-Path $PSScriptRoot -Parent
$SERVICE_NAME = "RiskNoXSupervisor"
$CONTROL_SCRIPT = Join-Path $REPO_ROOT "RiskNoXServiceControl.ps1"

# Test results
$Script:TestResults = @()
$Script:PassedTests = 0
$Script:FailedTests = 0

# Color output
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
        $Script:PassedTests++
    }
    else {
        Write-Host "  ✗ " -NoNewline -ForegroundColor Red
        Write-Host "$TestName" -ForegroundColor White
        $Script:FailedTests++
    }
    
    if ($Details) {
        Write-Host "      $Details" -ForegroundColor Gray
    }
    
    $Script:TestResults += [PSCustomObject]@{
        Test = $TestName
        Passed = $Passed
        Details = $Details
        Timestamp = Get-Date
    }
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

# Test 1: Verify script is running as Administrator
function Test-RunningAsAdmin {
    Write-Host "Test 1: Checking if running as Administrator..." -ForegroundColor Cyan
    
    if (Test-Administrator) {
        Write-TestResult "Running as Administrator" $true "Required for testing"
        return $true
    }
    else {
        Write-TestResult "Running as Administrator" $false "This test script requires admin privileges"
        return $false
    }
}

# Test 2: Verify service exists
function Test-ServiceExists {
    Write-Host ""
    Write-Host "Test 2: Checking if service exists..." -ForegroundColor Cyan
    
    $service = Get-Service -Name $SERVICE_NAME -ErrorAction SilentlyContinue
    
    if ($service) {
        Write-TestResult "Service exists" $true "Service: $SERVICE_NAME"
        return $true
    }
    else {
        Write-TestResult "Service exists" $false "Service not found: $SERVICE_NAME"
        Write-Host ""
        Write-Host "  Please install the service first:" -ForegroundColor Yellow
        Write-Host "  .\RiskNoXServiceControl.ps1 install" -ForegroundColor White
        return $false
    }
}

# Test 3: Verify service is running
function Test-ServiceRunning {
    Write-Host ""
    Write-Host "Test 3: Checking if service is running..." -ForegroundColor Cyan
    
    $service = Get-Service -Name $SERVICE_NAME -ErrorAction SilentlyContinue
    
    if ($service -and $service.Status -eq 'Running') {
        Write-TestResult "Service is running" $true "Status: $($service.Status)"
        return $true
    }
    else {
        $status = if ($service) { $service.Status } else { "Not Found" }
        Write-TestResult "Service is running" $false "Status: $status"
        
        if ($service -and $service.Status -eq 'Stopped') {
            Write-Host ""
            Write-Host "  Please start the service first:" -ForegroundColor Yellow
            Write-Host "  .\RiskNoXServiceControl.ps1 start" -ForegroundColor White
        }
        return $false
    }
}

# Test 4: Verify service runs as LocalSystem
function Test-LocalSystemAccount {
    Write-Host ""
    Write-Host "Test 4: Verifying service runs as LocalSystem..." -ForegroundColor Cyan
    
    try {
        $wmiService = Get-WmiObject -Class Win32_Service -Filter "Name='$SERVICE_NAME'" -ErrorAction Stop
        
        if ($wmiService.StartName -eq "LocalSystem") {
            Write-TestResult "Service runs as LocalSystem" $true "Account: $($wmiService.StartName)"
            return $true
        }
        else {
            Write-TestResult "Service runs as LocalSystem" $false "Account: $($wmiService.StartName)"
            return $false
        }
    }
    catch {
        Write-TestResult "Service runs as LocalSystem" $false "Could not query service account"
        return $false
    }
}

# Test 5: Verify SDDL protection is applied
function Test-SDDLProtection {
    Write-Host ""
    Write-Host "Test 5: Verifying SDDL protection..." -ForegroundColor Cyan
    
    try {
        $sddlOutput = sc.exe sdshow $SERVICE_NAME 2>&1 | Out-String
        
        if ($LASTEXITCODE -eq 0) {
            # Check if SDDL contains deny rule for administrators (D;;WPDT;;;BA)
            if ($sddlOutput -match "D;.*WPDT.*BA") {
                Write-TestResult "SDDL protection applied" $true "Deny rule found for administrators"
                Write-Host "      SDDL: $($sddlOutput.Trim().Substring(0, [Math]::Min(60, $sddlOutput.Length)))..." -ForegroundColor Gray
                return $true
            }
            else {
                Write-TestResult "SDDL protection applied" $false "No deny rule found"
                return $false
            }
        }
        else {
            Write-TestResult "SDDL protection applied" $false "Could not query SDDL"
            return $false
        }
    }
    catch {
        Write-TestResult "SDDL protection applied" $false "Error: $($_.Exception.Message)"
        return $false
    }
}

# Test 6: Try to stop service via PowerShell (should FAIL)
function Test-CannotStopViaPowerShell {
    Write-Host ""
    Write-Host "Test 6: Attempting to stop service via PowerShell..." -ForegroundColor Cyan
    Write-Host "      (This should FAIL with Access Denied)" -ForegroundColor Gray
    
    try {
        $originalStatus = (Get-Service -Name $SERVICE_NAME).Status
        
        # Attempt to stop (should fail)
        Stop-Service -Name $SERVICE_NAME -Force -ErrorAction Stop
        
        Start-Sleep -Seconds 2
        $newStatus = (Get-Service -Name $SERVICE_NAME).Status
        
        # If we got here and service stopped, protection failed
        if ($newStatus -eq 'Stopped') {
            Write-TestResult "Cannot stop via PowerShell" $false "Service was stopped (Protection FAILED!)"
            
            # Restart the service for remaining tests
            Write-Host "      Restarting service for remaining tests..." -ForegroundColor Yellow
            Start-Service -Name $SERVICE_NAME
            Start-Sleep -Seconds 3
            
            return $false
        }
        else {
            # This shouldn't happen - Stop-Service should throw exception
            Write-TestResult "Cannot stop via PowerShell" $true "Service remained running"
            return $true
        }
    }
    catch {
        # Exception is expected (Access Denied or Cannot open - both indicate protection)
        if ($_.Exception.Message -match "Access is denied|Cannot stop|Cannot open") {
            Write-TestResult "Cannot stop via PowerShell" $true "Access Denied (expected)"
            Write-Host "      Error: $($_.Exception.Message)" -ForegroundColor Gray
            return $true
        }
        else {
            Write-TestResult "Cannot stop via PowerShell" $false "Unexpected error: $($_.Exception.Message)"
            return $false
        }
    }
}

# Test 7: Try to stop service via sc.exe (should FAIL)
function Test-CannotStopViaSC {
    Write-Host ""
    Write-Host "Test 7: Attempting to stop service via sc.exe..." -ForegroundColor Cyan
    Write-Host "      (This should FAIL with Access Denied)" -ForegroundColor Gray
    
    try {
        $originalStatus = (Get-Service -Name $SERVICE_NAME).Status
        
        # Attempt to stop (should fail)
        $result = sc.exe stop $SERVICE_NAME 2>&1 | Out-String
        $exitCode = $LASTEXITCODE
        
        Start-Sleep -Seconds 2
        $newStatus = (Get-Service -Name $SERVICE_NAME).Status
        
        # Check if service is still running
        if ($newStatus -eq 'Running' -and $exitCode -ne 0) {
            Write-TestResult "Cannot stop via sc.exe" $true "Access Denied (expected)"
            Write-Host "      Error Code: $exitCode" -ForegroundColor Gray
            return $true
        }
        elseif ($newStatus -eq 'Stopped') {
            Write-TestResult "Cannot stop via sc.exe" $false "Service was stopped (Protection FAILED!)"
            
            # Restart the service
            Write-Host "      Restarting service for remaining tests..." -ForegroundColor Yellow
            Start-Service -Name $SERVICE_NAME
            Start-Sleep -Seconds 3
            
            return $false
        }
        else {
            Write-TestResult "Cannot stop via sc.exe" $true "Service still running"
            return $true
        }
    }
    catch {
        Write-TestResult "Cannot stop via sc.exe" $false "Unexpected error: $($_.Exception.Message)"
        return $false
    }
}

# Test 8: Try to modify service configuration (should FAIL)
function Test-CannotModifyConfig {
    Write-Host ""
    Write-Host "Test 8: Attempting to modify service configuration..." -ForegroundColor Cyan
    Write-Host "      (This should FAIL with Access Denied)" -ForegroundColor Gray
    
    try {
        # Try to change startup type
        $result = sc.exe config $SERVICE_NAME start= manual 2>&1 | Out-String
        $exitCode = $LASTEXITCODE
        
        if ($exitCode -ne 0) {
            Write-TestResult "Cannot modify configuration" $true "Access Denied (expected)"
            Write-Host "      Error Code: $exitCode" -ForegroundColor Gray
            return $true
        }
        else {
            Write-TestResult "Cannot modify configuration" $false "Configuration was changed (Protection FAILED!)"
            
            # Restore automatic startup
            Write-Host "      Restoring automatic startup..." -ForegroundColor Yellow
            sc.exe config $SERVICE_NAME start= auto | Out-Null
            
            return $false
        }
    }
    catch {
        Write-TestResult "Cannot modify configuration" $true "Exception thrown (expected)"
        return $true
    }
}

# Test 9: Try to delete service via sc.exe (should FAIL)
function Test-CannotDeleteService {
    Write-Host ""
    Write-Host "Test 9: Attempting to delete service via sc.exe..." -ForegroundColor Cyan
    Write-Host "      (This should FAIL - service is running)" -ForegroundColor Gray
    
    try {
        # First, service must be stopped to delete, which should fail
        $stopResult = sc.exe stop $SERVICE_NAME 2>&1 | Out-String
        $stopExitCode = $LASTEXITCODE
        
        if ($stopExitCode -eq 0) {
            # If stop succeeded, try delete
            $deleteResult = sc.exe delete $SERVICE_NAME 2>&1 | Out-String
            $deleteExitCode = $LASTEXITCODE
            
            if ($deleteExitCode -eq 0) {
                Write-TestResult "Cannot delete service" $false "Service was deleted (Protection FAILED!)"
                
                Write-Host ""
                Write-Host "  CRITICAL: Service was deleted! Protection failed!" -ForegroundColor Red
                Write-Host "  You need to reinstall the service:" -ForegroundColor Yellow
                Write-Host "  .\RiskNoXServiceControl.ps1 install" -ForegroundColor White
                
                return $false
            }
        }
        
        # If we got here, stop or delete failed (expected)
        Write-TestResult "Cannot delete service" $true "Service protected from deletion"
        return $true
    }
    catch {
        Write-TestResult "Cannot delete service" $true "Exception thrown (expected)"
        return $true
    }
}

# Test 10: Verify auto-restart configuration
function Test-AutoRestartConfig {
    Write-Host ""
    Write-Host "Test 10: Verifying auto-restart configuration..." -ForegroundColor Cyan
    
    try {
        $failureConfig = sc.exe qfailure $SERVICE_NAME 2>&1 | Out-String
        
        if ($LASTEXITCODE -eq 0) {
            if ($failureConfig -match "RESTART") {
                Write-TestResult "Auto-restart configured" $true "Service will restart on failure"
                return $true
            }
            else {
                Write-TestResult "Auto-restart configured" $false "No restart action found"
                return $false
            }
        }
        else {
            Write-TestResult "Auto-restart configured" $false "Could not query failure actions"
            return $false
        }
    }
    catch {
        Write-TestResult "Auto-restart configured" $false "Error: $($_.Exception.Message)"
        return $false
    }
}

# Test 11: Verify control script can stop service
function Test-ControlScriptCanStop {
    Write-Host ""
    Write-Host "Test 11: Verifying RiskNoXServiceControl.ps1 can stop service..." -ForegroundColor Cyan
    
    if (!(Test-Path $CONTROL_SCRIPT)) {
        Write-TestResult "Control script can stop" $false "Script not found: $CONTROL_SCRIPT"
        return $false
    }
    
    try {
        # Stop via control script
        Write-Host "      Executing: .\RiskNoXServiceControl.ps1 stop" -ForegroundColor Gray
        & $CONTROL_SCRIPT stop 2>&1 | Out-Null
        
        Start-Sleep -Seconds 5
        
        $service = Get-Service -Name $SERVICE_NAME
        
        if ($service.Status -eq 'Stopped') {
            Write-TestResult "Control script can stop" $true "Service stopped successfully"
            
            # Restart for remaining tests
            Write-Host "      Restarting service..." -ForegroundColor Gray
            & $CONTROL_SCRIPT start 2>&1 | Out-Null
            Start-Sleep -Seconds 10
            
            return $true
        }
        else {
            Write-TestResult "Control script can stop" $false "Service still running after script execution"
            return $false
        }
    }
    catch {
        Write-TestResult "Control script can stop" $false "Error: $($_.Exception.Message)"
        return $false
    }
}

# Test 12: Verify service is protected after restart
function Test-ProtectionPersistsAfterRestart {
    Write-Host ""
    Write-Host "Test 12: Verifying protection persists after restart..." -ForegroundColor Cyan
    
    # Verify service is running
    $service = Get-Service -Name $SERVICE_NAME
    
    if ($service.Status -ne 'Running') {
        Write-TestResult "Protection persists" $false "Service not running"
        return $false
    }
    
    # Check SDDL protection
    try {
        $sddlOutput = sc.exe sdshow $SERVICE_NAME 2>&1 | Out-String
        
        if ($LASTEXITCODE -eq 0 -and $sddlOutput -match "D;.*WPDT.*BA") {
            Write-TestResult "Protection persists" $true "SDDL protection still active"
            
            # Try to stop again (should fail)
            try {
                Stop-Service -Name $SERVICE_NAME -Force -ErrorAction Stop
                Write-Host "      WARNING: Service stopped after restart!" -ForegroundColor Yellow
                
                # Restart
                Start-Service -Name $SERVICE_NAME
                Start-Sleep -Seconds 3
                
                return $false
            }
            catch {
                Write-Host "      Confirmed: Cannot stop service (Access Denied)" -ForegroundColor Gray
                return $true
            }
        }
        else {
            Write-TestResult "Protection persists" $false "SDDL protection not active"
            return $false
        }
    }
    catch {
        Write-TestResult "Protection persists" $false "Error checking protection"
        return $false
    }
}

# Test 13: Simulate crash and verify auto-restart
function Test-AutoRestartOnCrash {
    Write-Host ""
    Write-Host "Test 13: Testing auto-restart on crash..." -ForegroundColor Cyan
    Write-Host "      (This will kill the service process)" -ForegroundColor Yellow
    
    try {
        # Get service PID
        $service = Get-Service -Name $SERVICE_NAME
        if ($service.Status -ne 'Running') {
            Write-TestResult "Auto-restart on crash" $false "Service not running"
            return $false
        }
        
        # Get the process
        $serviceProcess = Get-WmiObject Win32_Service -Filter "Name='$SERVICE_NAME'"
        $servicePid = $serviceProcess.ProcessId
        
        if ($servicePid -eq 0) {
            Write-TestResult "Auto-restart on crash" $false "Could not get service PID"
            return $false
        }
        
        Write-Host "      Service PID: $servicePid" -ForegroundColor Gray
        Write-Host "      Killing process..." -ForegroundColor Gray
        
        # Kill the process
        Stop-Process -Id $servicePid -Force -ErrorAction SilentlyContinue
        
        # Wait for auto-restart
        Write-Host "      Waiting 10 seconds for auto-restart..." -ForegroundColor Gray
        Start-Sleep -Seconds 10
        
        # Check if service restarted
        $service = Get-Service -Name $SERVICE_NAME
        
        # Service is restarting if it's Running or StartPending
        if ($service.Status -eq 'Running' -or $service.Status -eq 'StartPending') {
            $newServiceProcess = Get-WmiObject Win32_Service -Filter "Name='$SERVICE_NAME'"
            $newPid = $newServiceProcess.ProcessId
            
            if ($service.Status -eq 'StartPending') {
                Write-TestResult "Auto-restart on crash" $true "Service is restarting (Status: StartPending)"
                return $true
            }
            elseif ($newPid -ne $servicePid -and $newPid -gt 0) {
                Write-TestResult "Auto-restart on crash" $true "Service restarted automatically (new PID: $newPid)"
                return $true
            }
            else {
                Write-TestResult "Auto-restart on crash" $false "Service running but PID unchanged"
                return $false
            }
        }
        else {
            Write-TestResult "Auto-restart on crash" $false "Service did not restart (Status: $($service.Status))"
            
            # Manually restart for remaining tests
            Write-Host "      Manually restarting service..." -ForegroundColor Yellow
            & $CONTROL_SCRIPT start 2>&1 | Out-Null
            Start-Sleep -Seconds 10
            
            return $false
        }
    }
    catch {
        Write-TestResult "Auto-restart on crash" $false "Error: $($_.Exception.Message)"
        return $false
    }
}

# Test 14: Test protection status command
function Test-ProtectionStatusCommand {
    Write-Host ""
    Write-Host "Test 14: Verifying protection status is shown correctly..." -ForegroundColor Cyan
    
    if (!(Test-Path $CONTROL_SCRIPT)) {
        Write-TestResult "Protection status command" $false "Script not found"
        return $false
    }
    
    try {
        # Run status command and capture output
        $statusOutput = & $CONTROL_SCRIPT status 2>&1 | Out-String
        
        # Debug: show what we captured (first 500 chars)
        Write-Host "      Captured output length: $($statusOutput.Length) characters" -ForegroundColor Gray
        
        # Check if output contains protection information
        # Just check if both "Protection" and "ENABLED" appear in the output
        if (($statusOutput -match "Protection") -and ($statusOutput -match "ENABLED") -and ($statusOutput -match "Admins cannot stop")) {
            Write-TestResult "Protection status command" $true "Status correctly shows protection enabled"
            return $true
        }
        else {
            Write-Host "      Debug - Has 'Protection': $($statusOutput -match 'Protection')" -ForegroundColor DarkGray
            Write-Host "      Debug - Has 'ENABLED': $($statusOutput -match 'ENABLED')" -ForegroundColor DarkGray
            Write-Host "      Debug - Has 'Admins': $($statusOutput -match 'Admins')" -ForegroundColor DarkGray
            Write-TestResult "Protection status command" $false "Status does not show protection information"
            return $false
        }
    }
    catch {
        Write-TestResult "Protection status command" $false "Error: $($_.Exception.Message)"
        return $false
    }
}

# Generate summary report
function Show-TestSummary {
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  TEST SUMMARY" -ForegroundColor White
    Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host ""
    
    $totalTests = $Script:PassedTests + $Script:FailedTests
    $passPercentage = if ($totalTests -gt 0) { [math]::Round(($Script:PassedTests / $totalTests) * 100, 1) } else { 0 }
    
    Write-Host "  Total Tests:    $totalTests" -ForegroundColor White
    Write-Host "  Passed:         " -NoNewline
    Write-Host "$($Script:PassedTests)" -ForegroundColor Green
    Write-Host "  Failed:         " -NoNewline
    Write-Host "$($Script:FailedTests)" -ForegroundColor $(if ($Script:FailedTests -eq 0) { "Green" } else { "Red" })
    Write-Host "  Pass Rate:      $passPercentage%" -ForegroundColor $(if ($passPercentage -eq 100) { "Green" } elseif ($passPercentage -ge 80) { "Yellow" } else { "Red" })
    Write-Host ""
    
    # Overall assessment
    if ($Script:FailedTests -eq 0) {
        Write-Host "╔═══════════════════════════════════════════════════════════╗" -ForegroundColor Green
        Write-Host "║                                                           ║" -ForegroundColor Green
        Write-Host "║   ✓ SERVICE PROTECTION VERIFIED - ALL TESTS PASSED!      ║" -ForegroundColor Green
        Write-Host "║                                                           ║" -ForegroundColor Green
        Write-Host "╚═══════════════════════════════════════════════════════════╝" -ForegroundColor Green
        Write-Host ""
        Write-Host "  Service is fully protected:" -ForegroundColor White
        Write-Host "  • Running as LocalSystem (highest privileges)" -ForegroundColor Green
        Write-Host "  • SDDL protection active (admins cannot stop)" -ForegroundColor Green
        Write-Host "  • Auto-restarts on failure" -ForegroundColor Green
        Write-Host "  • Only manageable via RiskNoXServiceControl.ps1" -ForegroundColor Green
    }
    elseif ($passPercentage -ge 80) {
        Write-Host "╔═══════════════════════════════════════════════════════════╗" -ForegroundColor Yellow
        Write-Host "║                                                           ║" -ForegroundColor Yellow
        Write-Host "║   ⚠ SERVICE PROTECTION PARTIAL - SOME TESTS FAILED       ║" -ForegroundColor Yellow
        Write-Host "║                                                           ║" -ForegroundColor Yellow
        Write-Host "╚═══════════════════════════════════════════════════════════╝" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  Review failed tests above and reapply protection:" -ForegroundColor Yellow
        Write-Host "  .\RiskNoXServiceControl.ps1 protect" -ForegroundColor White
    }
    else {
        Write-Host "╔═══════════════════════════════════════════════════════════╗" -ForegroundColor Red
        Write-Host "║                                                           ║" -ForegroundColor Red
        Write-Host "║   ✗ SERVICE PROTECTION FAILED - MULTIPLE ISSUES          ║" -ForegroundColor Red
        Write-Host "║                                                           ║" -ForegroundColor Red
        Write-Host "╚═══════════════════════════════════════════════════════════╝" -ForegroundColor Red
        Write-Host ""
        Write-Host "  Critical issues detected! Reinstall and reapply protection:" -ForegroundColor Red
        Write-Host "  1. .\RiskNoXServiceControl.ps1 uninstall" -ForegroundColor White
        Write-Host "  2. .\RiskNoXServiceControl.ps1 install" -ForegroundColor White
    }
    
    Write-Host ""
    
    # Export results
    $reportFile = Join-Path $REPO_ROOT "logs\protection-test-report.json"
    $reportDir = Split-Path $reportFile -Parent
    
    if (!(Test-Path $reportDir)) {
        New-Item -ItemType Directory -Path $reportDir -Force | Out-Null
    }
    
    $reportData = @{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        TotalTests = $totalTests
        PassedTests = $Script:PassedTests
        FailedTests = $Script:FailedTests
        PassPercentage = $passPercentage
        TestResults = $Script:TestResults
    }
    
    $reportData | ConvertTo-Json -Depth 10 | Out-File $reportFile -Encoding UTF8
    Write-Host "  Test report saved: $reportFile" -ForegroundColor Gray
    Write-Host ""
}

# Main execution
function Main {
    Write-TestHeader "RiskNoX Service Protection Verification Tests"
    
    Write-Host "This script will verify that the service is properly protected and" -ForegroundColor White
    Write-Host "that administrators cannot stop or modify the service through Windows." -ForegroundColor White
    Write-Host ""
    Write-Host "Tests will:" -ForegroundColor Cyan
    Write-Host "  • Verify LocalSystem account and SDDL protection" -ForegroundColor White
    Write-Host "  • Attempt to stop service (should fail)" -ForegroundColor White
    Write-Host "  • Attempt to modify configuration (should fail)" -ForegroundColor White
    Write-Host "  • Verify auto-restart on crash" -ForegroundColor White
    Write-Host "  • Verify RiskNoXServiceControl.ps1 can manage service" -ForegroundColor White
    Write-Host ""
    
    $continue = Read-Host "Continue with tests? (yes/no)"
    if ($continue -ne "yes") {
        Write-Host "Tests cancelled" -ForegroundColor Yellow
        return
    }
    
    # Run all tests
    $test1 = Test-RunningAsAdmin
    if (!$test1) {
        Write-Host ""
        Write-Host "ERROR: Administrator privileges required" -ForegroundColor Red
        return
    }
    
    $test2 = Test-ServiceExists
    if (!$test2) {
        Write-Host ""
        Write-Host "ERROR: Service not found. Cannot continue tests." -ForegroundColor Red
        return
    }
    
    $test3 = Test-ServiceRunning
    if (!$test3) {
        Write-Host ""
        Write-Host "ERROR: Service not running. Cannot continue tests." -ForegroundColor Red
        return
    }
    
    # Continue with remaining tests
    Test-LocalSystemAccount
    Test-SDDLProtection
    Test-CannotStopViaPowerShell
    Test-CannotStopViaSC
    Test-CannotModifyConfig
    Test-CannotDeleteService
    Test-AutoRestartConfig
    Test-ControlScriptCanStop
    Test-ProtectionPersistsAfterRestart
    Test-AutoRestartOnCrash
    Test-ProtectionStatusCommand
    
    # Show summary
    Show-TestSummary
}

# Run main
Main
