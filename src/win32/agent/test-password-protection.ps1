# Test Password Protection
# Quick test script for password protection functionality

Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  RiskNoX Service Control - Password Protection Test" -ForegroundColor White
Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""

$REPO_ROOT = Split-Path -Parent $PSScriptRoot
if (-not $REPO_ROOT) {
    $REPO_ROOT = $PSScriptRoot
}

$PASSWORD_FILE = Join-Path $REPO_ROOT "config\.service_password"
$DEFAULT_PASSWORD = "RiskNoX@2024"

Write-Host "Test Configuration:" -ForegroundColor Yellow
Write-Host "  Repository Root: $REPO_ROOT"
Write-Host "  Password File: $PASSWORD_FILE"
Write-Host "  Default Password: $DEFAULT_PASSWORD"
Write-Host ""

# Test 1: Check if password file exists
Write-Host "Test 1: Check Password File" -ForegroundColor Cyan
if (Test-Path $PASSWORD_FILE) {
    Write-Host "  ✓ Password file exists" -ForegroundColor Green
    $hash = Get-Content $PASSWORD_FILE -Raw
    Write-Host "  Hash: $($hash.Substring(0, 16))..." -ForegroundColor Gray
} else {
    Write-Host "  ⚠ Password file does not exist (will be created on first use)" -ForegroundColor Yellow
}
Write-Host ""

# Test 2: Generate hash for default password
Write-Host "Test 2: Generate Default Password Hash" -ForegroundColor Cyan
$defaultHash = Get-FileHash -InputStream ([System.IO.MemoryStream]::new([System.Text.Encoding]::UTF8.GetBytes($DEFAULT_PASSWORD))) -Algorithm SHA256
Write-Host "  Default password hash: $($defaultHash.Hash)" -ForegroundColor Gray
Write-Host ""

# Test 3: Validate default password
Write-Host "Test 3: Validate Default Password" -ForegroundColor Cyan
if (Test-Path $PASSWORD_FILE) {
    $storedHash = (Get-Content $PASSWORD_FILE -Raw).Trim()
    if ($storedHash -eq $defaultHash.Hash) {
        Write-Host "  ✓ Default password is still in use" -ForegroundColor Green
    } else {
        Write-Host "  ✓ Password has been changed from default" -ForegroundColor Green
    }
} else {
    Write-Host "  ⚠ Password file not initialized yet" -ForegroundColor Yellow
}
Write-Host ""

# Test 4: Test start command syntax
Write-Host "Test 4: Command Syntax Examples" -ForegroundColor Cyan
Write-Host "  Start service:" -ForegroundColor White
Write-Host "    .\RiskNoXServiceControl.ps1 start -Password 'RiskNoX@2024'" -ForegroundColor Gray
Write-Host ""
Write-Host "  Stop service:" -ForegroundColor White
Write-Host "    .\RiskNoXServiceControl.ps1 stop -Password 'RiskNoX@2024'" -ForegroundColor Gray
Write-Host ""
Write-Host "  Restart service:" -ForegroundColor White
Write-Host "    .\RiskNoXServiceControl.ps1 restart -Password 'RiskNoX@2024'" -ForegroundColor Gray
Write-Host ""

# Test 5: Check backend server
Write-Host "Test 5: Check Backend Server" -ForegroundColor Cyan
try {
    $response = Invoke-RestMethod -Uri "http://localhost:5001/health" -Method GET -TimeoutSec 5 -ErrorAction Stop
    Write-Host "  ✓ Backend server is running" -ForegroundColor Green
    Write-Host "  Status: $($response.status)" -ForegroundColor Gray
    Write-Host "  Port: $($response.port)" -ForegroundColor Gray
} catch {
    Write-Host "  ✗ Backend server is not running" -ForegroundColor Red
    Write-Host "  Start with: python service_control_backend.py" -ForegroundColor Yellow
}
Write-Host ""

# Test 6: Test API endpoint
Write-Host "Test 6: Test API Status Endpoint" -ForegroundColor Cyan
try {
    $response = Invoke-RestMethod -Uri "http://localhost:5001/api/service/status" -Method GET -TimeoutSec 10 -ErrorAction Stop
    Write-Host "  ✓ Status endpoint is working" -ForegroundColor Green
    if ($response.service_exists) {
        Write-Host "  Service Status: $($response.status)" -ForegroundColor Gray
    } else {
        Write-Host "  Service is not installed" -ForegroundColor Yellow
    }
} catch {
    Write-Host "  ✗ Could not reach status endpoint" -ForegroundColor Red
}
Write-Host ""

# Test 7: Security reminder
Write-Host "Security Reminders:" -ForegroundColor Yellow
Write-Host "  • Change default password after installation" -ForegroundColor White
Write-Host "  • Use strong passwords (12+ characters)" -ForegroundColor White
Write-Host "  • Never commit passwords to version control" -ForegroundColor White
Write-Host "  • Keep password file secure (config\.service_password)" -ForegroundColor White
Write-Host ""

Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  Test Complete" -ForegroundColor White
Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""

Write-Host "Next Steps:" -ForegroundColor Cyan
Write-Host "  1. Test start with password: .\RiskNoXServiceControl.ps1 start -Password 'RiskNoX@2024'"
Write-Host "  2. Open web interface: http://localhost:5001"
Write-Host "  3. Change default password (see PASSWORD-PROTECTION.md)"
Write-Host ""
