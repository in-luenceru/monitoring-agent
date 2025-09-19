# Monitoring Agent Control Test Script
# Tests all major functionality of the monitoring agent control scripts

Write-Host "=======================================" -ForegroundColor Yellow
Write-Host "Monitoring Agent Control Test Suite" -ForegroundColor Yellow  
Write-Host "=======================================" -ForegroundColor Yellow
Write-Host ""

$testsPassed = 0
$testsFailed = 0

function Test-Function {
    param(
        [string]$TestName,
        [scriptblock]$TestCode
    )
    
    Write-Host "Testing: $TestName" -ForegroundColor Cyan
    try {
        $result = & $TestCode
        if ($result) {
            Write-Host "✓ PASSED: $TestName" -ForegroundColor Green
            $script:testsPassed++
        } else {
            Write-Host "✗ FAILED: $TestName" -ForegroundColor Red
            $script:testsFailed++
        }
    } catch {
        Write-Host "✗ ERROR: $TestName - $($_.Exception.Message)" -ForegroundColor Red
        $script:testsFailed++
    }
    Write-Host ""
}

# Change to monitoring agent directory
$agentPath = "c:\Users\ANANDHU\OneDrive\Desktop\monitoring-agent"
Set-Location $agentPath

Write-Host "Testing Windows Implementation" -ForegroundColor Yellow
Write-Host "=======================================" -ForegroundColor Yellow

# Test 1: Help command
Test-Function "Help Command" {
    $output = & ".\monitoring-agent-control.ps1" help 2>&1
    return ($output -match "USAGE:")
}

# Test 2: Version command
Test-Function "Version Command" {
    $output = & ".\monitoring-agent-control.ps1" -Version 2>&1
    return ($output -match "v4\.8\.0")
}

# Test 3: Status command
Test-Function "Status Command" {
    $output = & ".\monitoring-agent-control.ps1" status 2>&1
    return ($output -match "Monitoring Agent Status")
}

# Test 4: Configuration validation
Test-Function "Configuration File Exists" {
    return (Test-Path "windows\etc\OSSEC.CONF")
}

# Test 5: Client keys exist
Test-Function "Client Keys Exist" {
    return (Test-Path "windows\etc\client.keys")
}

# Test 6: Binary exists
Test-Function "Agent Binary Exists" {
    return (Test-Path "windows\bin\MONITORING_AGENT.EXE")
}

# Test 7: Stop command (should work even if not running)
Test-Function "Stop Command" {
    $output = & ".\monitoring-agent-control.ps1" stop 2>&1
    return ($output -match "Stopped")
}

# Test 8: Test connection (should show manager details)
Test-Function "Test Configuration" {
    $output = & ".\monitoring-agent-control.ps1" test 2>&1
    return (-not ($output -match "ERROR"))
}

Write-Host "=======================================" -ForegroundColor Yellow
Write-Host "Test Results Summary" -ForegroundColor Yellow
Write-Host "=======================================" -ForegroundColor Yellow
Write-Host "Passed: $testsPassed" -ForegroundColor Green
Write-Host "Failed: $testsFailed" -ForegroundColor Red

if ($testsFailed -eq 0) {
    Write-Host ""
    Write-Host "🎉 All tests passed! The monitoring agent control script is working correctly." -ForegroundColor Green
    Write-Host ""
    Write-Host "Next steps to fully deploy:" -ForegroundColor Cyan
    Write-Host "1. Set up your Wazuh manager server" -ForegroundColor White
    Write-Host "2. Run: .\monitoring-agent-control.ps1 enroll <manager-ip>" -ForegroundColor White
    Write-Host "3. Run: .\monitoring-agent-control.ps1 start" -ForegroundColor White
    Write-Host "4. Run: .\monitoring-agent-control.ps1 status" -ForegroundColor White
} else {
    Write-Host ""
    Write-Host "⚠️ Some tests failed. Please check the implementation." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Manual Test Instructions:" -ForegroundColor Yellow
Write-Host "=======================================" -ForegroundColor Yellow
Write-Host "1. Test enrollment with a real manager IP:" -ForegroundColor White
Write-Host "   .\monitoring-agent-control.ps1 enroll <manager-ip>" -ForegroundColor Gray
Write-Host ""
Write-Host "2. Test agent start:" -ForegroundColor White
Write-Host "   .\monitoring-agent-control.ps1 start" -ForegroundColor Gray
Write-Host ""
Write-Host "3. Test agent status:" -ForegroundColor White
Write-Host "   .\monitoring-agent-control.ps1 status" -ForegroundColor Gray
Write-Host ""
Write-Host "4. Test agent stop:" -ForegroundColor White
Write-Host "   .\monitoring-agent-control.ps1 stop" -ForegroundColor Gray
Write-Host ""