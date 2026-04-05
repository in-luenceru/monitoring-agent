#Requires -Version 5.1

<#
.SYNOPSIS
    Comprehensive pre-build validation script for RiskNoX Monitoring Agent installer

.DESCRIPTION
    This script performs exhaustive validation to ensure ALL required components
    are present and properly configured before building the installer. It validates
    every file and directory referenced in the NSI script.

.EXAMPLE
    .\validate-installer-files.ps1
    Performs full validation with detailed output

.EXAMPLE
    .\validate-installer-files.ps1 -Quick
    Performs basic validation only

.EXAMPLE
    .\validate-installer-files.ps1 -Detailed
    Performs detailed validation with file size and signature checks
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [switch]$Quick,
    
    [Parameter(Mandatory=$false)]
    [switch]$Detailed,
    
    [Parameter(Mandatory=$false)]
    [switch]$Fix
)

# Color output functions
function Write-Success { param([string]$Message) Write-Host "  ✓ $Message" -ForegroundColor Green }
function Write-Info { param([string]$Message) Write-Host "  ℹ $Message" -ForegroundColor Cyan }
function Write-Warning { param([string]$Message) Write-Host "  ⚠ $Message" -ForegroundColor Yellow }
function Write-Error { param([string]$Message) Write-Host "  ✗ $Message" -ForegroundColor Red }
function Write-Header { 
    param([string]$Message) 
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  $Message" -ForegroundColor White
    Write-Host "═══════════════════════════════════════════════════════════" -ForegroundColor Cyan
}

# Global counters
$script:TotalChecks = 0
$script:PassedChecks = 0
$script:FailedChecks = 0
$script:WarningChecks = 0
$script:ValidationResults = @()

function Test-FileExists {
    param(
        [string]$FilePath,
        [string]$Description,
        [bool]$Required = $true,
        [string]$Category = "General"
    )
    
    $script:TotalChecks++
    $result = @{
        Path = $FilePath
        Description = $Description
        Category = $Category
        Required = $Required
        Exists = $false
        Size = 0
        Status = "Failed"
    }
    
    if (Test-Path $FilePath) {
        $script:PassedChecks++
        $item = Get-Item $FilePath
        $result.Exists = $true
        $result.Size = $item.Length
        $result.Status = "Passed"
        
        $sizeStr = if ($item.Length -gt 1MB) { "{0:N1} MB" -f ($item.Length/1MB) } 
                   elseif ($item.Length -gt 1KB) { "{0:N1} KB" -f ($item.Length/1KB) }
                   else { "$($item.Length) bytes" }
        
        if ($Detailed) {
            $lastModified = $item.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")
            Write-Success "$Description ($sizeStr, modified: $lastModified)"
        } else {
            Write-Success "$Description ($sizeStr)"
        }
    } else {
        if ($Required) {
            $script:FailedChecks++
            $result.Status = "Failed"
            Write-Error "$Description - REQUIRED FILE MISSING"
        } else {
            $script:WarningChecks++
            $result.Status = "Warning"
            Write-Warning "$Description - Optional file missing"
        }
    }
    
    $script:ValidationResults += $result
    return $result.Exists
}

function Test-DirectoryExists {
    param(
        [string]$DirectoryPath,
        [string]$Description,
        [bool]$Required = $true,
        [string]$Category = "Directory"
    )
    
    $script:TotalChecks++
    $result = @{
        Path = $DirectoryPath
        Description = $Description
        Category = $Category
        Required = $Required
        Exists = $false
        Size = 0
        Status = "Failed"
    }
    
    if (Test-Path $DirectoryPath -PathType Container) {
        $script:PassedChecks++
        $result.Exists = $true
        $result.Status = "Passed"
        
        $fileCount = 0
        $totalSize = 0
        try {
            $files = Get-ChildItem $DirectoryPath -Recurse -File -ErrorAction SilentlyContinue
            $fileCount = $files.Count
            $totalSize = ($files | Measure-Object -Property Length -Sum).Sum
        } catch {
            $fileCount = "Unknown"
        }
        
        $result.Size = $totalSize
        
        if ($fileCount -is [int]) {
            $sizeStr = if ($totalSize -gt 1MB) { "{0:N1} MB" -f ($totalSize/1MB) } 
                       elseif ($totalSize -gt 1KB) { "{0:N1} KB" -f ($totalSize/1KB) }
                       else { "$totalSize bytes" }
            Write-Success "$Description ($fileCount files, $sizeStr)"
        } else {
            Write-Success "$Description (directory exists)"
        }
    } else {
        if ($Required) {
            $script:FailedChecks++
            $result.Status = "Failed"
            Write-Error "$Description - REQUIRED DIRECTORY MISSING"
        } else {
            $script:WarningChecks++
            $result.Status = "Warning"
            Write-Warning "$Description - Optional directory missing"
        }
    }
    
    $script:ValidationResults += $result
    return $result.Exists
}

function Test-ExecutableSignature {
    param(
        [string]$ExePath,
        [string]$Description
    )
    
    if (!(Test-Path $ExePath)) {
        return $false
    }
    
    try {
        $signature = Get-AuthenticodeSignature $ExePath
        if ($signature.Status -eq "Valid") {
            Write-Success "$Description - Digitally signed (Valid)"
        } elseif ($signature.Status -eq "NotSigned") {
            Write-Warning "$Description - Not digitally signed"
        } else {
            Write-Warning "$Description - Signature status: $($signature.Status)"
        }
        return $true
    } catch {
        Write-Warning "$Description - Could not check signature: $($_.Exception.Message)"
        return $false
    }
}

function Test-PowerShellScript {
    param(
        [string]$ScriptPath,
        [string]$Description
    )
    
    if (!(Test-Path $ScriptPath)) {
        return $false
    }
    
    try {
        # Basic syntax check using AST
        $errors = $null
        $null = [System.Management.Automation.Language.Parser]::ParseFile($ScriptPath, [ref]$null, [ref]$errors)
        
        if ($errors.Count -eq 0) {
            Write-Success "$Description - PowerShell syntax OK"
        } else {
            Write-Warning "$Description - $($errors.Count) syntax issues detected"
            if ($Detailed) {
                foreach ($error in $errors) {
                    Write-Host "    Line $($error.Extent.StartLineNumber): $($error.Message)" -ForegroundColor Yellow
                }
            }
        }
        return $true
    } catch {
        Write-Warning "$Description - Could not validate syntax: $($_.Exception.Message)"
        return $false
    }
}

function Test-PowerShell7 {
    Write-Header "PowerShell 7 Detection"
    
    $pwsh7Locations = @(
        "$env:ProgramFiles\PowerShell\7\pwsh.exe",
        "${env:ProgramFiles(x86)}\PowerShell\7\pwsh.exe",
        "$env:LOCALAPPDATA\Microsoft\WindowsApps\pwsh.exe"
    )
    
    $foundPwsh7 = $false
    foreach ($location in $pwsh7Locations) {
        if (Test-Path $location) {
            try {
                $version = & $location --version 2>$null
                Write-Success "Found PowerShell 7 at: $location"
                Write-Info "Version: $version"
                $foundPwsh7 = $true
                break
            } catch {
                Write-Warning "PowerShell 7 found but not working at: $location"
            }
        }
    }
    
    if (!$foundPwsh7) {
        Write-Warning "PowerShell 7 not found - installer will use Windows PowerShell 5.1"
        Write-Info "Recommendation: Install PowerShell 7 for better performance"
        Write-Info "Download from: https://github.com/PowerShell/PowerShell/releases"
    }
    
    return $foundPwsh7
}

function Show-ValidationSummary {
    Write-Header "Comprehensive Validation Summary"
    
    # Group results by category
    $categories = $script:ValidationResults | Group-Object -Property Category
    
    Write-Host ""
    Write-Host "Results by Category:" -ForegroundColor Cyan
    foreach ($category in $categories) {
        $passed = ($category.Group | Where-Object { $_.Status -eq "Passed" }).Count
        $failed = ($category.Group | Where-Object { $_.Status -eq "Failed" }).Count
        $warnings = ($category.Group | Where-Object { $_.Status -eq "Warning" }).Count
        
        Write-Host "  $($category.Name): " -NoNewline -ForegroundColor White
        Write-Host "$passed passed" -NoNewline -ForegroundColor Green
        if ($failed -gt 0) {
            Write-Host ", $failed failed" -NoNewline -ForegroundColor Red
        }
        if ($warnings -gt 0) {
            Write-Host ", $warnings warnings" -NoNewline -ForegroundColor Yellow
        }
        Write-Host ""
    }
    
    Write-Host ""
    Write-Host "Overall Results:" -ForegroundColor Cyan
    Write-Host "  Total Checks: $script:TotalChecks" -ForegroundColor White
    Write-Host "  Passed: $script:PassedChecks" -ForegroundColor Green
    Write-Host "  Failed: $script:FailedChecks" -ForegroundColor Red
    Write-Host "  Warnings: $script:WarningChecks" -ForegroundColor Yellow
    Write-Host ""
    
    $successRate = [math]::Round(($script:PassedChecks / $script:TotalChecks) * 100, 1)
    Write-Host "Success Rate: $successRate%" -ForegroundColor $(if ($successRate -gt 90) { "Green" } elseif ($successRate -gt 70) { "Yellow" } else { "Red" })
    
    # Calculate total size
    $totalSize = ($script:ValidationResults | Where-Object { $_.Exists } | Measure-Object -Property Size -Sum).Sum
    $totalSizeStr = if ($totalSize -gt 1GB) { "{0:N1} GB" -f ($totalSize/1GB) }
                    elseif ($totalSize -gt 1MB) { "{0:N1} MB" -f ($totalSize/1MB) }
                    else { "{0:N1} KB" -f ($totalSize/1KB) }
    Write-Host "Total Size of Components: $totalSizeStr" -ForegroundColor Cyan
    
    if ($script:FailedChecks -eq 0) {
        Write-Host ""
        Write-Host "🎉 VALIDATION PASSED!" -ForegroundColor Green
        Write-Host "The installer can be built successfully." -ForegroundColor Green
        Write-Host ""
        Write-Info "Ready to build installer with command:"
        Write-Host "  .\build-installer.ps1" -ForegroundColor Yellow
        return $true
    } else {
        Write-Host ""
        Write-Host "❌ VALIDATION FAILED!" -ForegroundColor Red
        Write-Host "Fix the failed checks before building the installer." -ForegroundColor Red
        
        # Show failed items
        $failedItems = $script:ValidationResults | Where-Object { $_.Status -eq "Failed" }
        if ($failedItems.Count -gt 0) {
            Write-Host ""
            Write-Host "Failed Items:" -ForegroundColor Red
            foreach ($item in $failedItems) {
                Write-Host "  ✗ $($item.Description) - $($item.Path)" -ForegroundColor Red
            }
        }
        return $false
    }
}

# Main validation execution
try {
    Write-Host ""
    Write-Host "╔═══════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║                                                           ║" -ForegroundColor Cyan
    Write-Host "║     RiskNoX Monitoring Agent - Installer Validation     ║" -ForegroundColor Cyan
    Write-Host "║                 Comprehensive File Check                 ║" -ForegroundColor Cyan
    Write-Host "║                                                           ║" -ForegroundColor Cyan
    Write-Host "╚═══════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    
    # Check PowerShell 7 availability
    Test-PowerShell7
    
    # Check NSI script and license
    Write-Header "Installer Script Validation"
    Test-FileExists "RiskNoX-Installer.nsi" "NSIS Installer Script" $true "Installer"
    Test-FileExists "LICENSE" "License File" $true "Installer"
    
    # Core executable files - EXACTLY as referenced in NSI
    Write-Header "Core Executable Files"
    Test-FileExists "monitoring-agent.exe" "Main Monitoring Agent" $true "Core"
    Test-FileExists "monitoring-agent-original.exe" "Original Monitoring Agent" $false "Core"
    Test-FileExists "monitoring-agent-eventchannel.exe" "Event Channel Agent" $false "Core"
    Test-FileExists "MonitoringAgentService.exe" "Monitoring Agent Service" $false "Core"
    Test-FileExists "agent-auth.exe" "Agent Authentication" $true "Core"
    Test-FileExists "manage_agents.exe" "Agent Management Tool" $true "Core"
    Test-FileExists "win32ui.exe" "Windows UI Application" $false "Core"
    
    if ($Detailed -and !$Quick) {
        Test-ExecutableSignature "monitoring-agent.exe" "Main Agent"
        Test-ExecutableSignature "agent-auth.exe" "Auth Tool"
        Test-ExecutableSignature "manage_agents.exe" "Management Tool"
    }
    
    # Python scripts - Backend services
    Write-Header "Python Backend Services"
    Test-FileExists "backend_server.py" "Backend Server" $true "Python"
    Test-FileExists "service_control_backend.py" "Service Control Backend" $true "Python"
    Test-FileExists "agent_poll.py" "Agent Polling Service" $true "Python"
    
    # ALL PowerShell management scripts
    Write-Header "PowerShell Management Scripts"
    $psScripts = @(
        @("RiskNoXServiceControl.ps1", "Primary Service Control", $true),
        @("UnifiedAgentControl.ps1", "Unified Agent Control", $true),
        @("RiskNoX-Control.ps1", "RiskNoX Control Script", $true),
        @("MonitoringAgentControl.ps1", "Monitoring Agent Control", $true),
        @("RiskNoX-Agent-Installer.ps1", "Agent Installer Script", $true),
        @("MonitoringAgentAutoStart.ps1", "Auto-Start Script", $true),
        @("RobustAutoStart.ps1", "Robust Auto-Start", $true),
        @("SetupAutoStartup.ps1", "Setup Auto-Startup", $true),
        @("change-password.ps1", "Password Change Utility", $true),
        @("test-password-protection.ps1", "Password Protection Test", $false),
        @("test-web-blocking.ps1", "Web Blocking Test", $false)
    )
    
    foreach ($script in $psScripts) {
        Test-FileExists $script[0] $script[1] $script[2] "PowerShell"
        if (!$Quick -and (Test-Path $script[0])) {
            Test-PowerShellScript $script[0] $script[1]
        }
    }
    
    # ALL DLL libraries
    Write-Header "Dynamic Link Libraries"
    $dlls = @(
        @("dbsync.dll", "Database Synchronization", $true),
        @("libfimdb.dll", "FIM Database Library", $true),
        @("libwazuhext.dll", "Wazuh Extension Library", $true),
        @("libwazuhshared.dll", "Wazuh Shared Library", $true),
        @("syscollector.dll", "System Collector", $true),
        @("sysinfo.dll", "System Information", $true),
        @("libgcc_s_dw2-1.dll", "GCC Runtime", $true),
        @("libstdc++-6.dll", "C++ Standard Library", $true),
        @("libwinpthread-1.dll", "Windows Pthread Library", $true),
        @("rsync.dll", "Rsync Library", $true)
    )
    
    foreach ($dll in $dlls) {
        Test-FileExists $dll[0] $dll[1] $dll[2] "DLL"
    }
    
    # Configuration files
    Write-Header "Configuration Files"
    $configs = @(
        @("ossec.conf", "Main Configuration", $true),
        @("ossec.conf.original", "Original Configuration", $false),
        @("ossec.conf.new", "New Configuration", $false),
        @("internal_options.conf", "Internal Options", $true),
        @("local_internal_options.conf", "Local Internal Options", $true),
        @("vista_sec.txt", "Vista Security Configuration", $true),
        @("wpk_root.pem", "WPK Root Certificate", $true),
        @("VERSION.json", "Version Information", $true),
        @("profile-10.template", "Profile Template", $true)
    )
    
    foreach ($config in $configs) {
        Test-FileExists $config[0] $config[1] $config[2] "Configuration"
    }
    
    # Batch and startup files
    Write-Header "Startup and Batch Files"
    Test-FileExists "auto-start-wrapper.bat" "Auto-Start Wrapper" $true "Startup"
    Test-FileExists "InstallAndStart-RiskNoX.bat" "Install and Start Script" $true "Startup"
    
    # Windows utilities
    Write-Header "Windows Setup Utilities"
    Test-FileExists "setup-iis.exe" "IIS Setup Utility" $false "Utilities"
    Test-FileExists "setup-syscheck.exe" "Syscheck Setup" $false "Utilities"
    Test-FileExists "setup-windows.exe" "Windows Setup" $false "Utilities"
    
    # Documentation files
    Write-Header "Documentation Files"
    $docs = @(
        @("help.txt", "Help Documentation", $true),
        @("help.txt.original", "Original Help", $false),
        @("ReadMe.txt", "ReadMe File", $true),
        @("changes.txt", "Changes Log", $true),
        @("INSTALLATION-GUIDE.md", "Installation Guide", $true)
    )
    
    foreach ($doc in $docs) {
        Test-FileExists $doc[0] $doc[1] $doc[2] "Documentation"
    }
    
    # State files
    Write-Header "State and Runtime Files"
    $stateFiles = @(
        @("monitoring-agent.state", "Agent State", $false),
        @("monitoring-.state", "Monitoring State", $false),
        @("wazuh-agent.state", "Wazuh Agent State", $false),
        @("monitoring-logcollector.state", "Log Collector State", $false),
        @("monitoring-agent.pid", "Agent PID", $false),
        @("ossec.log", "OSSEC Log", $false)
    )
    
    foreach ($stateFile in $stateFiles) {
        Test-FileExists $stateFile[0] $stateFile[1] $stateFile[2] "State"
    }
    
    # Supervisor system
    Write-Header "Service Supervisor System"
    Test-FileExists "dist\supervisor.exe" "Supervisor Executable" $false "Supervisor"
    Test-FileExists "supervisor\supervisor.py" "Supervisor Python Script" $true "Supervisor"
    Test-FileExists "supervisor\supervisor.spec" "Supervisor Spec File" $true "Supervisor"
    Test-FileExists "supervisor\requirements.txt" "Supervisor Requirements" $true "Supervisor"
    Test-FileExists "supervisor\remote_control_auth.py" "Remote Control Auth" $true "Supervisor"
    
    # Configuration system
    Write-Header "Configuration System"
    Test-DirectoryExists "config" "Configuration Directory" $false "Configuration"
    Test-FileExists "config\services.yml" "Services Configuration" $false "Configuration"
    Test-FileExists "config\settings.json" "Settings Configuration" $false "Configuration"
    Test-FileExists "config\process_inventory.json" "Process Inventory" $false "Configuration"
    Test-FileExists "config\supervisor_token.txt" "Supervisor Token" $false "Configuration"
    Test-FileExists "config\.service_password" "Service Password File" $false "Configuration"
    
    # Management tools
    Write-Header "Management Tools"
    Test-DirectoryExists "tools" "Tools Directory" $true "Tools"
    Test-FileExists "tools\nssm\win64\nssm.exe" "NSSM Service Manager (64-bit)" $true "Tools"
    Test-FileExists "tools\nssm\win32\nssm.exe" "NSSM Service Manager (32-bit)" $false "Tools"
    Test-FileExists "tools\nssm\ChangeLog.txt" "NSSM ChangeLog" $false "Tools"
    Test-FileExists "tools\nssm\README.txt" "NSSM README" $false "Tools"
    
    $toolScripts = @(
        "build.ps1", "deploy.ps1", "download_nssm.ps1", "enroll-agent.ps1",
        "install-dependencies.ps1", "install_service.ps1", "protect_service.ps1",
        "refresh-creds.ps1", "restart.ps1", "start.ps1", "status-enhanced.ps1",
        "status.ps1", "stop.ps1", "test-non-admin-access.ps1",
        "test-service-protection.ps1", "uninstall_service.ps1", "unprotect_service.ps1"
    )
    
    foreach ($tool in $toolScripts) {
        Test-FileExists "tools\$tool" "Tool: $tool" $false "Tools"
    }
    
    # Component directories
    if (!$Quick) {
        Write-Header "Component Directories"
        Test-DirectoryExists "active-response" "Active Response System" $false "Components"
        Test-DirectoryExists "shared" "Shared Resources" $false "Components"
        Test-DirectoryExists "ruleset" "Detection Ruleset" $false "Components"
        Test-DirectoryExists "suricata" "Suricata Network IDS" $false "Components"
        Test-DirectoryExists "npcap" "Npcap Network Driver" $false "Components"
        Test-DirectoryExists "vendor" "Vendor Libraries" $false "Components"
        Test-DirectoryExists "samples" "Sample Configurations" $false "Components"
        Test-DirectoryExists "state" "State Management" $false "Components"
        Test-DirectoryExists "rids" "Registry System" $false "Components"
        Test-DirectoryExists "queue" "Message Queue System" $false "Components"
        Test-DirectoryExists "build" "Build System" $false "Components"
    }
    
    # Show comprehensive results
    $validationPassed = Show-ValidationSummary
    
    if ($validationPassed) {
        Write-Host ""
        Write-Info "System is ready for installer build!"
        Write-Host ""
        Write-Info "Next steps:"
        Write-Host "  1. Build installer: .\build-installer.ps1" -ForegroundColor Green
        Write-Host "  2. Test installer on clean system" -ForegroundColor Green  
        Write-Host "  3. Verify service installation and startup" -ForegroundColor Green
        Write-Host ""
    } else {
        Write-Host ""
        Write-Info "Fix the issues above, then run validation again."
        Write-Info "For missing optional files, you can continue if desired."
        Write-Host ""
    }
    
    exit $(if ($validationPassed) { 0 } else { 1 })
}
catch {
    Write-Host ""
    Write-Error "VALIDATION ERROR: $($_.Exception.Message)"
    Write-Host ""
    Write-Host "Stack Trace:" -ForegroundColor Red
    Write-Host $_.ScriptStackTrace -ForegroundColor Red
    exit 1
}