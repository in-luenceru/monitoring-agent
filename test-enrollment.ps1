# Test enrollment with manager
param(
    [Parameter(Mandatory=$true)]
    [string]$ManagerIP
)

Write-Host "Testing Enrollment with Manager: $ManagerIP" -ForegroundColor Green

# Test network connectivity
Write-Host "`nTesting network connectivity..."
$tcpTest = Test-NetConnection -ComputerName $ManagerIP -Port 1515 -WarningAction SilentlyContinue
if ($tcpTest.TcpTestSucceeded) {
    Write-Host "✓ Manager is reachable on port 1515 (enrollment port)" -ForegroundColor Green
} else {
    Write-Host "✗ Cannot reach manager on port 1515" -ForegroundColor Red
    Write-Host "Make sure the manager is running and port 1515 is open"
}

# Test agent communication port
$tcpTest1514 = Test-NetConnection -ComputerName $ManagerIP -Port 1514 -WarningAction SilentlyContinue
if ($tcpTest1514.TcpTestSucceeded) {
    Write-Host "✓ Manager is reachable on port 1514 (agent communication port)" -ForegroundColor Green
} else {
    Write-Host "✗ Cannot reach manager on port 1514" -ForegroundColor Red
}

Write-Host "`n" + "="*50
Write-Host "To enroll with this manager, run:"
Write-Host ".\monitoring-agent-control.ps1 enroll $ManagerIP" -ForegroundColor Yellow
Write-Host "="*50