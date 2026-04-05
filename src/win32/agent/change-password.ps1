# Change Service Password
# Utility script to change the RiskNoX Service Control password

Write-Host ""
Write-Host "╔═══════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║                                                           ║" -ForegroundColor Cyan
Write-Host "║     RiskNoX Service Control - Change Password            ║" -ForegroundColor Cyan
Write-Host "║                                                           ║" -ForegroundColor Cyan
Write-Host "╚═══════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

$REPO_ROOT = $PSScriptRoot
$PASSWORD_FILE = Join-Path $REPO_ROOT "config\.service_password"
$DEFAULT_PASSWORD = "RiskNoX@2024"

# Ensure config directory exists
$configDir = Join-Path $REPO_ROOT "config"
if (!(Test-Path $configDir)) {
    New-Item -ItemType Directory -Path $configDir -Force | Out-Null
}

# Function to generate password hash
function Get-PasswordHash {
    param([string]$Password)
    $hash = Get-FileHash -InputStream ([System.IO.MemoryStream]::new([System.Text.Encoding]::UTF8.GetBytes($Password))) -Algorithm SHA256
    return $hash.Hash
}

# Function to verify password
function Test-PasswordMatch {
    param([string]$Password)
    
    if (!(Test-Path $PASSWORD_FILE)) {
        # No password file exists, check against default
        $defaultHash = Get-PasswordHash -Password $DEFAULT_PASSWORD
        $inputHash = Get-PasswordHash -Password $Password
        return ($inputHash -eq $defaultHash)
    }
    
    $storedHash = (Get-Content $PASSWORD_FILE -Raw).Trim()
    $inputHash = Get-PasswordHash -Password $Password
    return ($inputHash -eq $storedHash)
}

# Check current status
Write-Host "Current Status:" -ForegroundColor Yellow
if (Test-Path $PASSWORD_FILE) {
    Write-Host "  Password file: EXISTS" -ForegroundColor Green
    $hash = Get-Content $PASSWORD_FILE -Raw
    $defaultHash = Get-PasswordHash -Password $DEFAULT_PASSWORD
    if ($hash.Trim() -eq $defaultHash) {
        Write-Host "  Current password: DEFAULT (RiskNoX@2024)" -ForegroundColor Yellow
    } else {
        Write-Host "  Current password: CUSTOM" -ForegroundColor Green
    }
} else {
    Write-Host "  Password file: NOT FOUND" -ForegroundColor Red
    Write-Host "  Will be created with default password on first use" -ForegroundColor Gray
}
Write-Host ""

# Get current password
Write-Host "Enter Current Password:" -ForegroundColor Cyan
$currentPassword = Read-Host -AsSecureString
$currentPasswordPlain = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
    [Runtime.InteropServices.Marshal]::SecureStringToBSTR($currentPassword)
)

# Verify current password
if (!(Test-PasswordMatch -Password $currentPasswordPlain)) {
    Write-Host ""
    Write-Host "✗ Current password is incorrect!" -ForegroundColor Red
    Write-Host ""
    Write-Host "If you forgot your password:" -ForegroundColor Yellow
    Write-Host "  1. Delete password file: Remove-Item '$PASSWORD_FILE' -Force" -ForegroundColor White
    Write-Host "  2. Default password will be restored: RiskNoX@2024" -ForegroundColor White
    Write-Host ""
    exit 1
}

Write-Host "✓ Current password verified" -ForegroundColor Green
Write-Host ""

# Get new password
Write-Host "Enter New Password:" -ForegroundColor Cyan
$newPassword = Read-Host -AsSecureString
$newPasswordPlain = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
    [Runtime.InteropServices.Marshal]::SecureStringToBSTR($newPassword)
)

# Validate new password
if ($newPasswordPlain.Length -lt 8) {
    Write-Host ""
    Write-Host "✗ Password must be at least 8 characters long" -ForegroundColor Red
    Write-Host ""
    exit 1
}

if ($newPasswordPlain -eq $DEFAULT_PASSWORD) {
    Write-Host ""
    Write-Host "⚠ Warning: You are setting the default password" -ForegroundColor Yellow
    Write-Host "  This is not recommended for security reasons" -ForegroundColor Yellow
    $confirm = Read-Host "Continue anyway? (yes/no)"
    if ($confirm -ne "yes") {
        Write-Host "Password change cancelled" -ForegroundColor Gray
        exit 0
    }
}

# Confirm new password
Write-Host "Confirm New Password:" -ForegroundColor Cyan
$confirmPassword = Read-Host -AsSecureString
$confirmPasswordPlain = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
    [Runtime.InteropServices.Marshal]::SecureStringToBSTR($confirmPassword)
)

if ($newPasswordPlain -ne $confirmPasswordPlain) {
    Write-Host ""
    Write-Host "✗ Passwords do not match!" -ForegroundColor Red
    Write-Host ""
    exit 1
}

Write-Host ""

# Generate new hash and save
$newHash = Get-PasswordHash -Password $newPasswordPlain
Set-Content -Path $PASSWORD_FILE -Value $newHash -Force

Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Green
Write-Host "  ✓ Password Changed Successfully!" -ForegroundColor Green
Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Green
Write-Host ""

Write-Host "Password Details:" -ForegroundColor Cyan
Write-Host "  Length: $($newPasswordPlain.Length) characters" -ForegroundColor Gray
Write-Host "  Hash: $($newHash.Substring(0, 32))..." -ForegroundColor Gray
Write-Host "  Saved to: $PASSWORD_FILE" -ForegroundColor Gray
Write-Host ""

Write-Host "IMPORTANT:" -ForegroundColor Yellow
Write-Host "  • Remember your new password - it cannot be recovered" -ForegroundColor White
Write-Host "  • Use this password for all service control operations" -ForegroundColor White
Write-Host "  • If forgotten, delete password file to reset to default" -ForegroundColor White
Write-Host ""

Write-Host "Test Your New Password:" -ForegroundColor Cyan
Write-Host "  .\RiskNoXServiceControl.ps1 status" -ForegroundColor Gray
Write-Host "  .\RiskNoXServiceControl.ps1 start -Password 'YourNewPassword'" -ForegroundColor Gray
Write-Host ""

# Clear sensitive variables
$currentPasswordPlain = $null
$newPasswordPlain = $null
$confirmPasswordPlain = $null
[System.GC]::Collect()
