# Unified Security Agent - Installer Validation Script
# This script validates that all required files are present before building

param(
    [switch]$Detailed = $false
)

Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "  Unified Security Agent - File Validation" -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host ""

$ErrorCount = 0
$WarningCount = 0

function Test-FileExists {
    param(
        [string]$FilePath,
        [string]$Description,
        [bool]$Required = $true,
        [string]$Category = "General"
    )
    
    if (Test-Path $FilePath) {
        $Size = (Get-Item $FilePath).Length
        $SizeKB = [math]::Round($Size / 1KB, 2)
        Write-Host "  ✓ $Description" -ForegroundColor Green
        if ($Detailed) {
            Write-Host "    Path: $FilePath" -ForegroundColor Gray
            Write-Host "    Size: $SizeKB KB" -ForegroundColor Gray
        }
        return $true
    } else {
        if ($Required) {
            Write-Host "  ✗ $Description (MISSING - REQUIRED)" -ForegroundColor Red
            $script:ErrorCount++
        } else {
            Write-Host "  ⚠ $Description (Missing - Optional)" -ForegroundColor Yellow
            $script:WarningCount++
        }
        if ($Detailed) {
            Write-Host "    Expected Path: $FilePath" -ForegroundColor Gray
        }
        return $false
    }
}

# Core Executables
Write-Host "Core Executables:" -ForegroundColor White
Test-FileExists "monitoring-agent.exe" "Monitoring Agent Executable" $true "Core"
Test-FileExists "agent-auth.exe" "Agent Authentication" $true "Core"
Test-FileExists "manage_agents.exe" "Agent Management Tool" $true "Core"
Test-FileExists "MonitoringAgentService.exe" "Service Wrapper" $false "Core"

# Main Control Scripts
Write-Host "`nMain Control Scripts:" -ForegroundColor White
Test-FileExists "RiskNoXServiceControl.ps1" "Service Control Script" $true "Scripts"
Test-FileExists "UnifiedAgentControl.ps1" "Agent Control Script" $true "Scripts"

# DLL Libraries
Write-Host "`nDLL Libraries:" -ForegroundColor White
$dlls = @(
    "dbsync.dll", "libfimdb.dll", "libgcc_s_dw2-1.dll", "libstdc++-6.dll",
    "libwazuhext.dll", "libwazuhshared.dll", "libwinpthread-1.dll",
    "rsync.dll", "syscollector.dll", "sysinfo.dll"
)
foreach ($dll in $dlls) {
    Test-FileExists $dll "Library: $dll" $true "Libraries"
}

# Configuration Files
Write-Host "`nConfiguration Files:" -ForegroundColor White
Test-FileExists "ossec.conf" "Main Configuration" $true "Config"
Test-FileExists "internal_options.conf" "Internal Options" $true "Config"
Test-FileExists "local_internal_options.conf" "Local Options" $true "Config"
Test-FileExists "config\services.yml" "Supervisor Configuration" $true "Config"
Test-FileExists "config\settings.json" "Supervisor Settings" $true "Config"

# Supervisor Components
Write-Host "`nSupervisor Components:" -ForegroundColor White
Test-FileExists "dist\supervisor.exe" "Supervisor Executable" $true "Supervisor"
Test-FileExists "supervisor\supervisor.py" "Supervisor Python Script" $true "Supervisor"
Test-FileExists "supervisor\requirements.txt" "Supervisor Requirements" $true "Supervisor"

# Suricata IDS
Write-Host "`nSuricata Network IDS:" -ForegroundColor White
Test-FileExists "suricata\bin\suricata.exe" "Suricata Executable" $true "Suricata"
Test-FileExists "suricata\etc\suricata.yaml" "Suricata Configuration" $true "Suricata"
Test-FileExists "suricata\SuricataControl.ps1" "Suricata Control Script" $true "Suricata"

# Suricata Dependencies
Write-Host "`nSuricata Dependencies:" -ForegroundColor White
$suricataDlls = @(
    "suricata\bin\libGeoIP-1.dll", "suricata\bin\libjansson-4.dll",
    "suricata\bin\packet.dll", "suricata\bin\WinDivert.dll",
    "suricata\bin\wpcap.dll", "suricata\bin\nss3.dll"
)
foreach ($dll in $suricataDlls) {
    Test-FileExists $dll "Suricata: $(Split-Path $dll -Leaf)" $true "Suricata"
}

# Management Tools
Write-Host "`nManagement Tools:" -ForegroundColor White
$tools = @(
    "tools\install_service.ps1", "tools\install-dependencies.ps1",
    "tools\build.ps1", "tools\start.ps1", "tools\stop.ps1"
)
foreach ($tool in $tools) {
    Test-FileExists $tool "Tool: $(Split-Path $tool -Leaf)" $true "Tools"
}

# NSSM Service Manager
Write-Host "`nNSSM Service Manager:" -ForegroundColor White
Test-FileExists "tools\nssm\win64\nssm.exe" "NSSM 64-bit" $true "Tools"
Test-FileExists "tools\nssm\win32\nssm.exe" "NSSM 32-bit" $false "Tools"

# Active Response
Write-Host "`nActive Response System:" -ForegroundColor White
$arTools = @(
    "active-response\bin\netsh.exe", "active-response\bin\restart-monitoring.exe",
    "active-response\bin\restart-wazuh.exe", "active-response\bin\route-null.exe"
)
foreach ($tool in $arTools) {
    Test-FileExists $tool "AR: $(Split-Path $tool -Leaf)" $true "ActiveResponse"
}

# Installer Files
Write-Host "`nInstaller Files:" -ForegroundColor White
Test-FileExists "UnifiedSecurityAgent-Installer.nsi" "NSIS Installer Script" $true "Installer"
Test-FileExists "build-installer.bat" "Build Script" $false "Installer"
Test-FileExists "README.md" "Documentation" $true "Installer"
Test-FileExists "favicon.ico" "Application Icon" $true "Installer"
Test-FileExists "install.ico" "Install Icon" $true "Installer"
Test-FileExists "uninstall.ico" "Uninstall Icon" $true "Installer"

# Summary
Write-Host "`n=============================================" -ForegroundColor Cyan
Write-Host "  Validation Summary" -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan

if ($ErrorCount -eq 0) {
    Write-Host "✅ VALIDATION PASSED" -ForegroundColor Green
    Write-Host "   All required files are present" -ForegroundColor Green
    
    if ($WarningCount -gt 0) {
        Write-Host "⚠️  $WarningCount optional files missing" -ForegroundColor Yellow
    }
    
    Write-Host "`n🚀 Ready to build installer!" -ForegroundColor Green
    Write-Host "   Run: .\build-installer.bat" -ForegroundColor Cyan
    
} else {
    Write-Host "❌ VALIDATION FAILED" -ForegroundColor Red
    Write-Host "   $ErrorCount required files missing" -ForegroundColor Red
    
    if ($WarningCount -gt 0) {
        Write-Host "   $WarningCount optional files missing" -ForegroundColor Yellow
    }
    
    Write-Host "`n🔧 Please copy missing files before building installer" -ForegroundColor Yellow
    exit 1
}

Write-Host ""