# Production Readiness Test Script
# This script validates all monitoring agent functionality

Write-Host "🚀 MONITORING AGENT PRODUCTION READINESS TEST" -ForegroundColor Green
Write-Host "=" * 60 -ForegroundColor Yellow

$testResults = @()

# Test 1: Agent Status Detection
Write-Host "`n📊 Testing agent status detection..." -ForegroundColor Cyan
try {
    $statusResult = & ".\monitoring-agent-control.ps1" status 2>&1
    if ($statusResult -match "Configuration File: EXISTS") {
        $testResults += "✅ Status Detection: PASSED - Configuration properly detected"
    } else {
        $testResults += "❌ Status Detection: FAILED"
    }
} catch {
    $testResults += "❌ Status Detection: ERROR - $($_.Exception.Message)"
}

# Test 2: Agent Startup
Write-Host "`n🔄 Testing agent startup..." -ForegroundColor Cyan
try {
    $startResult = & ".\monitoring-agent-control.ps1" start 2>&1
    if ($startResult -match "started successfully|Started successfully") {
        $testResults += "✅ Agent Startup: PASSED - Agent starts correctly"
    } else {
        $testResults += "❌ Agent Startup: FAILED - $startResult"
    }
} catch {
    $testResults += "❌ Agent Startup: ERROR - $($_.Exception.Message)"
}

# Test 3: Manager Connectivity
Write-Host "`n🌐 Testing manager connectivity..." -ForegroundColor Cyan
try {
    $connectTest = Test-NetConnection -ComputerName localhost -Port 1514 -WarningAction SilentlyContinue
    if ($connectTest.TcpTestSucceeded) {
        $testResults += "✅ Manager Connectivity: PASSED - Port 1514 accessible"
    } else {
        $testResults += "❌ Manager Connectivity: FAILED - Cannot reach localhost:1514"
    }
} catch {
    $testResults += "❌ Manager Connectivity: ERROR - $($_.Exception.Message)"
}

# Test 4: Agent Registration on Manager
Write-Host "`n🔐 Testing agent registration..." -ForegroundColor Cyan
try {
    $agentList = docker exec wazuh-manager /var/ossec/bin/agent_control -l 2>&1
    if ($agentList -match "windows-testing") {
        $testResults += "✅ Agent Registration: PASSED - Agent visible on manager"
    } else {
        $testResults += "❌ Agent Registration: FAILED - Agent not found on manager"
    }
} catch {
    $testResults += "❌ Agent Registration: ERROR - $($_.Exception.Message)"
}

# Test 5: Alert Generation
Write-Host "`n📢 Testing alert generation..." -ForegroundColor Cyan
try {
    $alerts = docker exec wazuh-manager tail -5 /var/ossec/logs/alerts/alerts.log 2>&1
    if ($alerts -match "windows-testing") {
        $testResults += "✅ Alert Generation: PASSED - Alerts generated for agent"
    } else {
        $testResults += "❌ Alert Generation: FAILED - No alerts found"
    }
} catch {
    $testResults += "❌ Alert Generation: ERROR - $($_.Exception.Message)"
}

# Test 6: Configuration Validation
Write-Host "`n⚙️  Testing configuration validation..." -ForegroundColor Cyan
try {
    $configPath = "windows\etc\OSSEC.CONF"
    $clientKeysPath = "windows\etc\client.keys"
    
    if ((Test-Path $configPath) -and (Test-Path $clientKeysPath)) {
        $testResults += "✅ Configuration: PASSED - All config files present"
    } else {
        $testResults += "❌ Configuration: FAILED - Missing config files"
    }
} catch {
    $testResults += "❌ Configuration: ERROR - $($_.Exception.Message)"
}

# Display Results
Write-Host "`n" + "=" * 60 -ForegroundColor Yellow
Write-Host "🏁 PRODUCTION READINESS TEST RESULTS" -ForegroundColor Green
Write-Host "=" * 60 -ForegroundColor Yellow

foreach ($result in $testResults) {
    if ($result -match "✅") {
        Write-Host $result -ForegroundColor Green
    } else {
        Write-Host $result -ForegroundColor Red
    }
}

$passedTests = ($testResults | Where-Object { $_ -match "✅" }).Count
$totalTests = $testResults.Count

Write-Host "`n📈 Overall Score: $passedTests/$totalTests tests passed" -ForegroundColor $(if($passedTests -eq $totalTests){"Green"}else{"Yellow"})

if ($passedTests -eq $totalTests) {
    Write-Host "🎉 PRODUCTION READY! All tests passed." -ForegroundColor Green
} elseif ($passedTests -ge ($totalTests * 0.8)) {
    Write-Host "⚠️  MOSTLY READY - Minor issues detected" -ForegroundColor Yellow
} else {
    Write-Host "🚫 NOT READY - Critical issues need attention" -ForegroundColor Red
}

Write-Host "`n🔧 Production Commands:" -ForegroundColor Cyan
Write-Host "  Start Agent:    .\monitoring-agent-control.ps1 start" -ForegroundColor White
Write-Host "  Check Status:   .\monitoring-agent-control.ps1 status" -ForegroundColor White
Write-Host "  Stop Agent:     .\monitoring-agent-control.ps1 stop" -ForegroundColor White
Write-Host "  Enroll Agent:   .\monitoring-agent-control.ps1 enroll <manager-ip>" -ForegroundColor White
Write-Host "=" * 60 -ForegroundColor Yellow