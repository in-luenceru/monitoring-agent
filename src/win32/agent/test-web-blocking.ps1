# RiskNoX Web Blocking Test Script
# This script demonstrates the web blocking functionality

Write-Host "RiskNoX Web Blocking API Test" -ForegroundColor Cyan
Write-Host "================================" -ForegroundColor Cyan

$baseUrl = "http://localhost:5000/api/web-blocking"

# Test connection
Write-Host "`n1. Testing connection to RiskNoX Agent..." -ForegroundColor Yellow
try {
    $response = Invoke-RestMethod -Uri "$baseUrl/urls" -Method GET
    if ($response.success) {
        Write-Host "✅ Connected to RiskNoX Agent successfully!" -ForegroundColor Green
    }
} catch {
    Write-Host "❌ Failed to connect to RiskNoX Agent. Make sure it's running on port 5000." -ForegroundColor Red
    exit 1
}

# Get current blocked URLs
Write-Host "`n2. Current blocked websites:" -ForegroundColor Yellow
$blockedUrls = Invoke-RestMethod -Uri "$baseUrl/urls" -Method GET
if ($blockedUrls.urls.Count -gt 0) {
    foreach ($url in $blockedUrls.urls) {
        Write-Host "   - $($url.url) (blocked: $($url.blocked_at))" -ForegroundColor White
    }
} else {
    Write-Host "   No websites currently blocked" -ForegroundColor Gray
}

# Test blocking a website
$testUrl = "example-test-site.com"
Write-Host "`n3. Testing website blocking..." -ForegroundColor Yellow
Write-Host "   Blocking: $testUrl" -ForegroundColor White

try {
    $blockResponse = Invoke-RestMethod -Uri "$baseUrl/block" -Method POST -ContentType "application/json" -Body "{`"url`": `"$testUrl`"}"
    if ($blockResponse.success) {
        Write-Host "   ✅ Successfully blocked $testUrl" -ForegroundColor Green
    } else {
        Write-Host "   ❌ Failed to block $testUrl" -ForegroundColor Red
    }
} catch {
    Write-Host "   ❌ Error blocking website: $($_.Exception.Message)" -ForegroundColor Red
}

# Verify it was blocked
Write-Host "`n4. Verifying website was blocked..." -ForegroundColor Yellow
$updatedUrls = Invoke-RestMethod -Uri "$baseUrl/urls" -Method GET
$isBlocked = $updatedUrls.urls | Where-Object { $_.url -eq $testUrl }
if ($isBlocked) {
    Write-Host "   ✅ $testUrl is now in the blocked list" -ForegroundColor Green
} else {
    Write-Host "   ❌ $testUrl was not found in the blocked list" -ForegroundColor Red
}

# Test unblocking
Write-Host "`n5. Testing website unblocking..." -ForegroundColor Yellow
Write-Host "   Unblocking: $testUrl" -ForegroundColor White

try {
    $unblockResponse = Invoke-RestMethod -Uri "$baseUrl/unblock" -Method POST -ContentType "application/json" -Body "{`"url`": `"$testUrl`"}"
    if ($unblockResponse.success) {
        Write-Host "   ✅ Successfully unblocked $testUrl" -ForegroundColor Green
    } else {
        Write-Host "   ❌ Failed to unblock $testUrl" -ForegroundColor Red
    }
} catch {
    Write-Host "   ❌ Error unblocking website: $($_.Exception.Message)" -ForegroundColor Red
}

# Verify it was unblocked
Write-Host "`n6. Verifying website was unblocked..." -ForegroundColor Yellow
$finalUrls = Invoke-RestMethod -Uri "$baseUrl/urls" -Method GET
$stillBlocked = $finalUrls.urls | Where-Object { $_.url -eq $testUrl }
if (-not $stillBlocked) {
    Write-Host "   ✅ $testUrl is no longer in the blocked list" -ForegroundColor Green
} else {
    Write-Host "   ❌ $testUrl is still in the blocked list" -ForegroundColor Red
}

# Final status
Write-Host "`n7. Final blocked websites list:" -ForegroundColor Yellow
$finalUrls = Invoke-RestMethod -Uri "$baseUrl/urls" -Method GET
if ($finalUrls.urls.Count -gt 0) {
    foreach ($url in $finalUrls.urls) {
        Write-Host "   - $($url.url) (blocked: $($url.blocked_at))" -ForegroundColor White
    }
} else {
    Write-Host "   No websites currently blocked" -ForegroundColor Gray
}

Write-Host "`n🎉 Web blocking API test completed!" -ForegroundColor Cyan
Write-Host "You can now use the web interface at: http://localhost:5000" -ForegroundColor Cyan