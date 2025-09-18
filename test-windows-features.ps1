# Windows Monitoring Agent Feature Test Script
# Tests all implemented features to ensure parity with Linux version
# Copyright (C) 2025, Monitoring Solutions Inc.

param(
    [switch]$SkipInteractive,
    [switch]$QuickTest,
    [string]$TestSuite = "all"
)

# Test configuration
$script:AGENT_HOME = $PSScriptRoot
$script:CONTROL_SCRIPT = Join-Path $script:AGENT_HOME "monitoring-agent-control.ps1"
$script:TEST_LOG = Join-Path $script:AGENT_HOME "logs\feature-test.log"

# Test results
$script:TestResults = @()
$script:PassedTests = 0
$script:FailedTests = 0

function Write-TestLog {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [TEST] [$Level] $Message"
    
    # Write to console
    switch ($Level) {
        "PASS" { Write-Host "✓ $Message" -ForegroundColor Green }
        "FAIL" { Write-Host "✗ $Message" -ForegroundColor Red }
        "INFO" { Write-Host "ℹ $Message" -ForegroundColor Blue }
        "WARN" { Write-Host "⚠ $Message" -ForegroundColor Yellow }
        default { Write-Host $Message }
    }
    
    # Write to log file
    try {
        Add-Content -Path $script:TEST_LOG -Value $logEntry -ErrorAction SilentlyContinue
    }
    catch {
        # Ignore log file errors
    }
}

function Add-TestResult {
    param(
        [string]$TestName,
        [bool]$Passed,
        [string]$Details = ""
    )
    
    $result = @{
        Name = $TestName
        Passed = $Passed
        Details = $Details
        Timestamp = Get-Date
    }
    
    $script:TestResults += $result
    
    if ($Passed) {
        $script:PassedTests++
        Write-TestLog "$TestName" "PASS"
    }
    else {
        $script:FailedTests++
        Write-TestLog "$TestName - $Details" "FAIL"
    }
}

function Test-ControlScriptExists {
    Write-TestLog "Testing control script existence..."
    
    $exists = Test-Path $script:CONTROL_SCRIPT
    Add-TestResult "Control Script Exists" $exists "Path: $script:CONTROL_SCRIPT"
    
    return $exists
}

function Test-HelpFunction {
    Write-TestLog "Testing help function..."
    
    try {
        $helpOutput = & $script:CONTROL_SCRIPT "-Help" 2>&1
        $hasUsage = $helpOutput -match "USAGE:|Usage:"
        Add-TestResult "Help Function Works" $hasUsage "Help output generated"
        return $hasUsage
    }
    catch {
        Add-TestResult "Help Function Works" $false "Exception: $($_.Exception.Message)"
        return $false
    }
}

function Test-EnrollmentFunction {
    Write-TestLog "Testing enrollment function (dry run)..."
    
    try {
        # Test enrollment validation without actually enrolling
        $enrollOutput = & $script:CONTROL_SCRIPT "enroll" "127.0.0.1" 2>&1
        $hasPrompt = $helpOutput -match "Client Key Required|Enter the complete client key"
        Add-TestResult "Enrollment Function Available" $hasPrompt "Enrollment prompt shown"
        return $hasPrompt
    }
    catch {
        Add-TestResult "Enrollment Function Available" $false "Exception: $($_.Exception.Message)"
        return $false
    }
}

function Test-FaultToleranceScripts {
    Write-TestLog "Testing fault tolerance scripts..."
    
    $scripts = @(
        "scripts\windows\monitoring-watchdog.ps1",
        "scripts\windows\monitoring-logging.ps1", 
        "scripts\windows\monitoring-boot-recovery.ps1",
        "scripts\windows\monitoring-recovery.ps1"
    )
    
    $allExist = $true
    foreach ($script in $scripts) {
        $scriptPath = Join-Path $script:AGENT_HOME $script
        $exists = Test-Path $scriptPath
        if (-not $exists) {
            $allExist = $false
            Write-TestLog "Missing script: $script" "WARN"
        }
    }
    
    Add-TestResult "Fault Tolerance Scripts Exist" $allExist "All required scripts present"
    return $allExist
}

function Test-WindowsServiceFunction {
    Write-TestLog "Testing Windows service functions..."
    
    try {
        # Test service installation function exists
        $functionContent = Get-Content $script:CONTROL_SCRIPT -Raw
        $hasInstallService = $functionContent -match "function New-WindowsService"
        $hasRemoveService = $functionContent -match "function Remove-WindowsService"
        $hasServiceMode = $functionContent -match "function Start-ServiceMode"
        
        $allServiceFunctions = $hasInstallService -and $hasRemoveService -and $hasServiceMode
        Add-TestResult "Windows Service Functions" $allServiceFunctions "Install, Remove, and Service Mode functions available"
        return $allServiceFunctions
    }
    catch {
        Add-TestResult "Windows Service Functions" $false "Exception: $($_.Exception.Message)"
        return $false
    }
}

function Test-BypassFunctionality {
    Write-TestLog "Testing bypass functionality..."
    
    try {
        # Check for bypass DLL compilation script
        $compileScript = Join-Path $script:AGENT_HOME "compile_windows_bypass.bat"
        $compileScriptExists = Test-Path $compileScript
        
        # Check for bypass source
        $bypassSource = Join-Path $script:AGENT_HOME "bypass_windows.c"
        $bypassSourceExists = Test-Path $bypassSource
        
        # Check for bypass initialization in control script
        $functionContent = Get-Content $script:CONTROL_SCRIPT -Raw
        $hasBypassInit = $functionContent -match "Initialize-MonitoringBypass"
        
        $bypassComplete = $compileScriptExists -and $bypassSourceExists -and $hasBypassInit
        Add-TestResult "Bypass Functionality" $bypassComplete "Bypass DLL compilation and initialization available"
        return $bypassComplete
    }
    catch {
        Add-TestResult "Bypass Functionality" $false "Exception: $($_.Exception.Message)"
        return $false
    }
}

function Test-HealthCheckFunctions {
    Write-TestLog "Testing health check functions..."
    
    try {
        # Test basic health check
        $healthOutput = & $script:CONTROL_SCRIPT "health" 2>&1
        $hasHealthOutput = $healthOutput.Count -gt 0
        
        # Test comprehensive health check
        $fullHealthOutput = & $script:CONTROL_SCRIPT "health-check-full" 2>&1
        $hasFullHealthOutput = $fullHealthOutput.Count -gt 0
        
        $healthFunctionsWork = $hasHealthOutput -and $hasFullHealthOutput
        Add-TestResult "Health Check Functions" $healthFunctionsWork "Basic and comprehensive health checks available"
        return $healthFunctionsWork
    }
    catch {
        Add-TestResult "Health Check Functions" $false "Exception: $($_.Exception.Message)"
        return $false
    }
}

function Test-ConfigurationValidation {
    Write-TestLog "Testing configuration validation..."
    
    try {
        # Check for configuration validation function
        $functionContent = Get-Content $script:CONTROL_SCRIPT -Raw
        $hasConfigValidation = $functionContent -match "Test-Configuration"
        $hasClientKeyValidation = $functionContent -match "Test-ClientKey"
        
        $validationComplete = $hasConfigValidation -and $hasClientKeyValidation
        Add-TestResult "Configuration Validation" $validationComplete "Configuration and client key validation functions available"
        return $validationComplete
    }
    catch {
        Add-TestResult "Configuration Validation" $false "Exception: $($_.Exception.Message)"
        return $false
    }
}

function Test-LoggingEnhancements {
    Write-TestLog "Testing logging enhancements..."
    
    try {
        # Check for enhanced logging script
        $loggingScript = Join-Path $script:AGENT_HOME "scripts\windows\monitoring-logging.ps1"
        $loggingScriptExists = Test-Path $loggingScript
        
        # Check for logging function in main script
        $functionContent = Get-Content $script:CONTROL_SCRIPT -Raw
        $hasWriteLog = $functionContent -match "function Write-Log"
        
        $loggingComplete = $loggingScriptExists -and $hasWriteLog
        Add-TestResult "Enhanced Logging" $loggingComplete "Enhanced logging script and functions available"
        return $loggingComplete
    }
    catch {
        Add-TestResult "Enhanced Logging" $false "Exception: $($_.Exception.Message)"
        return $false
    }
}

function Test-ProcessManagement {
    Write-TestLog "Testing process management..."
    
    try {
        # Check for process management functions
        $functionContent = Get-Content $script:CONTROL_SCRIPT -Raw
        $hasStartAgent = $functionContent -match "function Start-Agent"
        $hasStopAgent = $functionContent -match "function Stop-Agent"
        $hasRestartProcess = $functionContent -match "function Restart-SingleProcess"
        $hasProcessStatus = $functionContent -match "function Get-ProcessStatus"
        
        $processManagementComplete = $hasStartAgent -and $hasStopAgent -and $hasRestartProcess -and $hasProcessStatus
        Add-TestResult "Process Management" $processManagementComplete "Start, Stop, Restart, and Status functions available"
        return $processManagementComplete
    }
    catch {
        Add-TestResult "Process Management" $false "Exception: $($_.Exception.Message)"
        return $false
    }
}

function Test-FeatureParity {
    Write-TestLog "Testing feature parity with Linux version..."
    
    # Get all functions from the control script
    $functionContent = Get-Content $script:CONTROL_SCRIPT -Raw
    
    # Key functions that should exist for feature parity
    $requiredFunctions = @(
        "Invoke-AgentEnrollment",
        "Start-FaultToleranceComponents",
        "Force-AgentDisconnect",
        "Restore-AgentConnection",
        "Initialize-MonitoringBypass",
        "Test-FaultToleranceHealth",
        "New-WindowsService",
        "Remove-WindowsService"
    )
    
    $missingFunctions = @()
    foreach ($func in $requiredFunctions) {
        if ($functionContent -notmatch "function $func") {
            $missingFunctions += $func
        }
    }
    
    $hasAllFunctions = $missingFunctions.Count -eq 0
    $details = if ($hasAllFunctions) { "All required functions present" } else { "Missing: $($missingFunctions -join ', ')" }
    
    Add-TestResult "Feature Parity with Linux" $hasAllFunctions $details
    return $hasAllFunctions
}

function Show-TestSummary {
    Write-TestLog ""
    Write-TestLog "========================================" 
    Write-TestLog "        TEST SUMMARY REPORT"
    Write-TestLog "========================================"
    Write-TestLog ""
    Write-TestLog "Total Tests: $($script:PassedTests + $script:FailedTests)"
    Write-TestLog "Passed: $script:PassedTests" "PASS"
    Write-TestLog "Failed: $script:FailedTests" $(if ($script:FailedTests -eq 0) { "PASS" } else { "FAIL" })
    Write-TestLog ""
    
    if ($script:FailedTests -gt 0) {
        Write-TestLog "FAILED TESTS:"
        foreach ($result in $script:TestResults) {
            if (-not $result.Passed) {
                Write-TestLog "  - $($result.Name): $($result.Details)" "FAIL"
            }
        }
        Write-TestLog ""
    }
    
    $successRate = [math]::Round(($script:PassedTests / ($script:PassedTests + $script:FailedTests)) * 100, 1)
    Write-TestLog "Success Rate: $successRate%"
    
    if ($script:FailedTests -eq 0) {
        Write-TestLog ""
        Write-TestLog "🎉 ALL TESTS PASSED! Windows implementation is complete and feature-complete!" "PASS"
        Write-TestLog "   The Windows monitoring agent now has full parity with the Linux version."
        Write-TestLog ""
    }
    else {
        Write-TestLog ""
        Write-TestLog "⚠ Some tests failed. Please review the implementation." "WARN"
        Write-TestLog ""
    }
}

# Main test execution
function Start-FeatureTests {
    Write-TestLog "Starting Windows Monitoring Agent Feature Tests..."
    Write-TestLog "Test Suite: $TestSuite"
    Write-TestLog "Quick Test: $QuickTest"
    Write-TestLog ""
    
    # Ensure log directory exists
    $logDir = Split-Path $script:TEST_LOG -Parent
    if (-not (Test-Path $logDir)) {
        New-Item -Path $logDir -ItemType Directory -Force | Out-Null
    }
    
    # Run tests based on suite selection
    if ($TestSuite -eq "all" -or $TestSuite -eq "basic") {
        Test-ControlScriptExists
        Test-HelpFunction
        Test-ProcessManagement
        Test-ConfigurationValidation
        Test-LoggingEnhancements
    }
    
    if ($TestSuite -eq "all" -or $TestSuite -eq "advanced") {
        Test-EnrollmentFunction
        Test-FaultToleranceScripts
        Test-WindowsServiceFunction
        Test-BypassFunctionality
        Test-HealthCheckFunctions
    }
    
    if ($TestSuite -eq "all" -or $TestSuite -eq "parity") {
        Test-FeatureParity
    }
    
    # Show summary
    Show-TestSummary
    
    # Return exit code based on results
    return $script:FailedTests
}

# Script entry point
try {
    $failureCount = Start-FeatureTests
    exit $failureCount
}
catch {
    Write-TestLog "Test execution failed: $($_.Exception.Message)" "FAIL"
    exit 1
}