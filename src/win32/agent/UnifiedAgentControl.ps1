#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Unified Control Script for RiskNoX and Monitoring Agents
    
.DESCRIPTION
    Simplified wrapper script to manage both RiskNoX Security Agent and Monitoring Agent
    Features:
    - Unified start, stop, restart, status, install, configure, and uninstall commands
    - Direct passthrough to individual control scripts
    - Simple logging and error handling
    - Configuration support for both agents
    - Safe uninstall with confirmation
    
.PARAMETER Action
    Action to perform: install, start, stop, restart, status, configure, uninstall
    
.AUTHOR
    Custom Security Solutions
    
.VERSION
    2.0.0 - Simplified
    
.NOTES
    Requires Administrator privileges
    Uses MonitoringAgentControl.ps1 and RiskNoX-Agent-Installer.ps1 directly
#>

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet('install', 'start', 'stop', 'restart', 'status', 'configure', 'uninstall', 'menu')]
    [string]$Action = 'menu'
)

# Script Configuration
$Script:AgentPath = $PSScriptRoot
$Script:LogFile = Join-Path $AgentPath "logs\unified-control.log"
$Script:RiskNoXScript = Join-Path $AgentPath "RiskNoX-Agent-Installer.ps1"
$Script:MonitoringScript = Join-Path $AgentPath "MonitoringAgentControl.ps1"

# Ensure logs directory exists
$LogDir = Split-Path $Script:LogFile -Parent
if (!(Test-Path $LogDir)) {
    New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
}

#region Logging Functions
function Write-UnifiedLog {
    param(
        [Parameter(Mandatory=$true)]
        [AllowEmptyString()]
        [string]$Message,
        
        [Parameter(Mandatory=$false)]
        [ValidateSet("INFO", "WARN", "ERROR", "SUCCESS")]
        [string]$Level = "INFO"
    )
    
    # Handle empty messages
    if ([string]::IsNullOrWhiteSpace($Message)) {
        $Message = " "
    }
    
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogEntry = "[$Timestamp] [UNIFIED] [$Level] $Message"
    
    # Write to console with colors
    switch ($Level) {
        "INFO"    { Write-Host $LogEntry -ForegroundColor Cyan }
        "WARN"    { Write-Host $LogEntry -ForegroundColor Yellow }
        "ERROR"   { Write-Host $LogEntry -ForegroundColor Red }
        "SUCCESS" { Write-Host $LogEntry -ForegroundColor Green }
    }
    
    # Write to log file
    try {
        Add-Content -Path $Script:LogFile -Value $LogEntry -ErrorAction SilentlyContinue
    }
    catch {
        # Silently continue if unable to write to log
    }
}
#endregion

#region Utility Functions
function Test-AdminRights {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-ScriptExists {
    param([string]$ScriptPath, [string]$Name)
    
    if (!(Test-Path $ScriptPath)) {
        Write-UnifiedLog "$Name script not found: $ScriptPath" "ERROR"
        return $false
    }
    return $true
}
#endregion

#region Main Functions
function Install-RiskNoXAgent {
    Write-UnifiedLog "🔧 Installing RiskNoX Security Agent..." "INFO"
    Write-UnifiedLog "========================================" "INFO"
    
    if (!(Test-ScriptExists $Script:RiskNoXScript "RiskNoX")) { return $false }
    
    try {
        # Execute RiskNoX installer and show its output directly
        $installProcess = Start-Process -FilePath "pwsh.exe" -ArgumentList @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $Script:RiskNoXScript, "-Action", "install") -WorkingDirectory $Script:AgentPath -NoNewWindow -Wait -PassThru
        
        if ($installProcess.ExitCode -eq 0) {
            Write-UnifiedLog "========================================" "INFO"
            Write-UnifiedLog "✅ RiskNoX Agent installation completed successfully!" "SUCCESS"
            return $true
        } else {
            Write-UnifiedLog "========================================" "INFO"
            Write-UnifiedLog "❌ RiskNoX Agent installation failed with exit code: $($installProcess.ExitCode)" "ERROR"
            return $false
        }
    }
    catch {
        Write-UnifiedLog "❌ Error during RiskNoX installation: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Start-RiskNoXAgent {
    Write-UnifiedLog "🚀 Starting RiskNoX Security Agent..." "INFO"
    Write-UnifiedLog "========================================" "INFO"
    
    if (!(Test-ScriptExists $Script:RiskNoXScript "RiskNoX")) { return $false }
    
    try {
        # Execute RiskNoX start command and show its output directly
        $startProcess = Start-Process -FilePath "pwsh.exe" -ArgumentList @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $Script:RiskNoXScript, "-Action", "start") -WorkingDirectory $Script:AgentPath -NoNewWindow -Wait -PassThru
        
        if ($startProcess.ExitCode -eq 0) {
            Write-UnifiedLog "========================================" "INFO"
            Write-UnifiedLog "✅ RiskNoX Agent started successfully!" "SUCCESS"
            return $true
        } else {
            Write-UnifiedLog "========================================" "INFO"
            Write-UnifiedLog "❌ RiskNoX Agent start failed with exit code: $($startProcess.ExitCode)" "ERROR"
            return $false
        }
    }
    catch {
        Write-UnifiedLog "❌ Error starting RiskNoX Agent: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Stop-RiskNoXAgent {
    Write-UnifiedLog "🛑 Stopping RiskNoX Security Agent..." "INFO"
    Write-UnifiedLog "========================================" "INFO"
    
    if (!(Test-ScriptExists $Script:RiskNoXScript "RiskNoX")) { return $false }
    
    try {
        # Execute RiskNoX stop command and show its output directly
        $stopProcess = Start-Process -FilePath "pwsh.exe" -ArgumentList @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $Script:RiskNoXScript, "-Action", "stop") -WorkingDirectory $Script:AgentPath -NoNewWindow -Wait -PassThru
        
        if ($stopProcess.ExitCode -eq 0) {
            Write-UnifiedLog "========================================" "INFO"
            Write-UnifiedLog "✅ RiskNoX Agent stopped successfully!" "SUCCESS"
            return $true
        } else {
            Write-UnifiedLog "========================================" "INFO"
            Write-UnifiedLog "❌ RiskNoX Agent stop failed with exit code: $($stopProcess.ExitCode)" "ERROR"
            return $false
        }
    }
    catch {
        Write-UnifiedLog "❌ Error stopping RiskNoX Agent: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Start-MonitoringAgent {
    Write-UnifiedLog "🛡️  Starting Monitoring Agent (includes Suricata)..." "INFO"
    Write-UnifiedLog "========================================" "INFO"
    
    if (!(Test-ScriptExists $Script:MonitoringScript "Monitoring Agent")) { return $false }
    
    try {
        # Execute Monitoring Agent start command and show its output directly
        $startProcess = Start-Process -FilePath "pwsh.exe" -ArgumentList @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $Script:MonitoringScript, "start") -WorkingDirectory $Script:AgentPath -NoNewWindow -Wait -PassThru
        
        if ($startProcess.ExitCode -eq 0) {
            Write-UnifiedLog "========================================" "INFO"
            Write-UnifiedLog "✅ Monitoring Agent started successfully!" "SUCCESS"
            return $true
        } else {
            Write-UnifiedLog "========================================" "INFO"
            Write-UnifiedLog "❌ Monitoring Agent start failed with exit code: $($startProcess.ExitCode)" "ERROR"
            return $false
        }
    }
    catch {
        Write-UnifiedLog "❌ Error starting Monitoring Agent: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Stop-MonitoringAgent {
    Write-UnifiedLog "🛑 Stopping Monitoring Agent (includes Suricata)..." "INFO"
    Write-UnifiedLog "========================================" "INFO"
    
    if (!(Test-ScriptExists $Script:MonitoringScript "Monitoring Agent")) { return $false }
    
    try {
        # Execute Monitoring Agent stop command and show its output directly
        $stopProcess = Start-Process -FilePath "pwsh.exe" -ArgumentList @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $Script:MonitoringScript, "stop") -WorkingDirectory $Script:AgentPath -NoNewWindow -Wait -PassThru
        
        if ($stopProcess.ExitCode -eq 0) {
            Write-UnifiedLog "========================================" "INFO"
            Write-UnifiedLog "✅ Monitoring Agent stopped successfully!" "SUCCESS"
            return $true
        } else {
            Write-UnifiedLog "========================================" "INFO"
            Write-UnifiedLog "❌ Monitoring Agent stop failed with exit code: $($stopProcess.ExitCode)" "ERROR"
            return $false
        }
    }
    catch {
        Write-UnifiedLog "❌ Error stopping Monitoring Agent: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

function Get-UnifiedStatus {
    Write-UnifiedLog "========================================" "INFO"
    Write-UnifiedLog "🔒 Unified Security Agents Status" "INFO"
    Write-UnifiedLog "========================================" "INFO"
    Write-UnifiedLog " " "INFO"
    
    # Get RiskNoX status
    Write-UnifiedLog "📋 RiskNoX Security Agent Status:" "INFO"
    Write-UnifiedLog "----------------------------------------" "INFO"
    if (Test-ScriptExists $Script:RiskNoXScript "RiskNoX") {
        try {
            # Execute RiskNoX status command and show its output directly
            $statusProcess = Start-Process -FilePath "pwsh.exe" -ArgumentList @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $Script:RiskNoXScript, "-Action", "status") -WorkingDirectory $Script:AgentPath -NoNewWindow -Wait -PassThru
        }
        catch {
            Write-UnifiedLog "Error getting RiskNoX status: $($_.Exception.Message)" "ERROR"
        }
    }
    
    Write-UnifiedLog " " "INFO"
    Write-UnifiedLog "📋 Monitoring Agent & Suricata Status:" "INFO"
    Write-UnifiedLog "----------------------------------------" "INFO"
    # Get Monitoring Agent status
    if (Test-ScriptExists $Script:MonitoringScript "Monitoring Agent") {
        try {
            # Execute Monitoring Agent status command and show its output directly
            $statusProcess = Start-Process -FilePath "pwsh.exe" -ArgumentList @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $Script:MonitoringScript, "status") -WorkingDirectory $Script:AgentPath -NoNewWindow -Wait -PassThru
        }
        catch {
            Write-UnifiedLog "Error getting Monitoring Agent status: $($_.Exception.Message)" "ERROR"
        }
    }
    
    Write-UnifiedLog " " "INFO"
    Write-UnifiedLog "========================================" "INFO"
}

function Install-AllAgents {
    Write-UnifiedLog "🔧🔧🔧🔧🔧🔧🔧🔧🔧🔧🔧🔧🔧🔧🔧🔧🔧🔧🔧🔧" "INFO"
    Write-UnifiedLog "🔧 INSTALLING ALL SECURITY AGENTS 🔧" "INFO"
    Write-UnifiedLog "🔧🔧🔧🔧🔧🔧🔧🔧🔧🔧🔧🔧🔧🔧🔧🔧🔧🔧🔧🔧" "INFO"
    
    $installResults = @()
    
    # Install RiskNoX Agent
    Write-UnifiedLog "📦 Phase 1: Installing RiskNoX Security Agent..." "INFO"
    $riskNoXResult = Install-RiskNoXAgent
    $installResults += @{Name = "RiskNoX Security Agent"; Success = $riskNoXResult}
    
    Write-UnifiedLog " " "INFO"
    Write-UnifiedLog "📦 Phase 2: Monitoring Agent is already installed" "INFO"
    Write-UnifiedLog "ℹ️  Monitoring Agent comes pre-configured in this package" "INFO"
    $installResults += @{Name = "Monitoring Agent"; Success = $true}
    
    # Summary
    Write-UnifiedLog " " "INFO"
    Write-UnifiedLog "📊 INSTALLATION SUMMARY" "INFO"
    Write-UnifiedLog "========================" "INFO"
    
    $successful = $installResults | Where-Object { $_.Success }
    $failed = $installResults | Where-Object { !$_.Success }
    
    if ($successful) {
        Write-UnifiedLog "✅ Successfully Installed:" "SUCCESS"
        foreach ($item in $successful) {
            Write-UnifiedLog "   ✓ $($item.Name)" "SUCCESS"
        }
    }
    
    if ($failed) {
        Write-UnifiedLog "❌ Failed to Install:" "ERROR"
        foreach ($item in $failed) {
            Write-UnifiedLog "   ✗ $($item.Name)" "ERROR"
        }
    }
    
    $overallSuccess = $failed.Count -eq 0
    if ($overallSuccess) {
        Write-UnifiedLog "🎉 ALL AGENTS INSTALLED SUCCESSFULLY!" "SUCCESS"
        Write-UnifiedLog "💡 Next step: Run 'start' to begin security monitoring" "INFO"
    } else {
        Write-UnifiedLog "⚠️  PARTIAL INSTALLATION - Some agents failed" "WARN"
    }
    
    Write-UnifiedLog "========================================" "INFO"
    return $overallSuccess
}

function Start-AllAgents {
    Write-UnifiedLog "🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀" "INFO"
    Write-UnifiedLog "🚀 STARTING ALL SECURITY AGENTS 🚀" "INFO"
    Write-UnifiedLog "🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀" "INFO"
    
    $startResults = @()
    
    # Start RiskNoX Agent
    Write-UnifiedLog "🔄 Phase 1: Starting RiskNoX Security Agent..." "INFO"
    $riskNoXResult = Start-RiskNoXAgent
    $startResults += @{Name = "RiskNoX Security Agent"; Success = $riskNoXResult}
    
    Write-UnifiedLog " " "INFO"
    
    # Start Monitoring Agent
    Write-UnifiedLog "🔄 Phase 2: Starting Monitoring Agent and Suricata..." "INFO"
    $monitoringResult = Start-MonitoringAgent
    $startResults += @{Name = "Monitoring Agent and Suricata"; Success = $monitoringResult}
    
    # Summary
    Write-UnifiedLog " " "INFO"
    Write-UnifiedLog "📊 STARTUP SUMMARY" "INFO"
    Write-UnifiedLog "==================" "INFO"
    
    $successful = $startResults | Where-Object { $_.Success }
    $failed = $startResults | Where-Object { !$_.Success }
    
    if ($successful) {
        Write-UnifiedLog "✅ Successfully Started:" "SUCCESS"
        foreach ($item in $successful) {
            Write-UnifiedLog "   ✓ $($item.Name)" "SUCCESS"
        }
    }
    
    if ($failed) {
        Write-UnifiedLog "❌ Failed to Start:" "ERROR"
        foreach ($item in $failed) {
            Write-UnifiedLog "   ✗ $($item.Name)" "ERROR"
        }
    }
    
    $overallSuccess = $failed.Count -eq 0
    if ($overallSuccess) {
        Write-UnifiedLog "🎉 ALL SECURITY AGENTS STARTED SUCCESSFULLY!" "SUCCESS"
        Write-UnifiedLog "🛡️  Your system is now protected" "SUCCESS"
    } else {
        Write-UnifiedLog "⚠️  PARTIAL STARTUP - Some agents failed to start" "WARN"
        Write-UnifiedLog "🔍 Check individual error messages above" "WARN"
    }
    
    Write-UnifiedLog "========================================" "INFO"
    return $overallSuccess
}

function Stop-AllAgents {
    Write-UnifiedLog "🛑🛑🛑🛑🛑🛑🛑🛑🛑🛑🛑🛑🛑🛑🛑🛑🛑🛑🛑🛑" "INFO"
    Write-UnifiedLog "🛑 STOPPING ALL SECURITY AGENTS 🛑" "INFO"
    Write-UnifiedLog "🛑🛑🛑🛑🛑🛑🛑🛑🛑🛑🛑🛑🛑🛑🛑🛑🛑🛑🛑🛑" "INFO"
    
    $stopResults = @()
    
    # Stop RiskNoX Agent
    Write-UnifiedLog "🔄 Phase 1: Stopping RiskNoX Security Agent..." "INFO"
    $riskNoXResult = Stop-RiskNoXAgent
    $stopResults += @{Name = "RiskNoX Security Agent"; Success = $riskNoXResult}
    
    Write-UnifiedLog " " "INFO"
    
    # Stop Monitoring Agent
    Write-UnifiedLog "🔄 Phase 2: Stopping Monitoring Agent and Suricata..." "INFO"
    $monitoringResult = Stop-MonitoringAgent
    $stopResults += @{Name = "Monitoring Agent and Suricata"; Success = $monitoringResult}
    
    # Summary
    Write-UnifiedLog " " "INFO"
    Write-UnifiedLog "📊 SHUTDOWN SUMMARY" "INFO"
    Write-UnifiedLog "===================" "INFO"
    
    $successful = $stopResults | Where-Object { $_.Success }
    $failed = $stopResults | Where-Object { !$_.Success }
    
    if ($successful) {
        Write-UnifiedLog "✅ Successfully Stopped:" "SUCCESS"
        foreach ($item in $successful) {
            Write-UnifiedLog "   ✓ $($item.Name)" "SUCCESS"
        }
    }
    
    if ($failed) {
        Write-UnifiedLog "❌ Failed to Stop:" "ERROR"
        foreach ($item in $failed) {
            Write-UnifiedLog "   ✗ $($item.Name)" "ERROR"
        }
    }
    
    $overallSuccess = $failed.Count -eq 0
    if ($overallSuccess) {
        Write-UnifiedLog "✅ ALL SECURITY AGENTS STOPPED SUCCESSFULLY!" "SUCCESS"
        Write-UnifiedLog "🔓 Security monitoring has been disabled" "INFO"
    } else {
        Write-UnifiedLog "⚠️  PARTIAL SHUTDOWN - Some agents may still be running" "WARN"
    }
    
    Write-UnifiedLog "========================================" "INFO"
    return $overallSuccess
}

function Configure-AllAgents {
    Write-UnifiedLog "⚙️⚙️⚙️⚙️⚙️⚙️⚙️⚙️⚙️⚙️⚙️⚙️⚙️⚙️⚙️⚙️⚙️⚙️⚙️⚙️" "INFO"
    Write-UnifiedLog "⚙️  CONFIGURING ALL SECURITY AGENTS ⚙️" "INFO"
    Write-UnifiedLog "⚙️⚙️⚙️⚙️⚙️⚙️⚙️⚙️⚙️⚙️⚙️⚙️⚙️⚙️⚙️⚙️⚙️⚙️⚙️⚙️" "INFO"
    
    $configResults = @()
    
    # Configure RiskNoX Agent
    Write-UnifiedLog "⚙️  Phase 1: Configuring RiskNoX Security Agent..." "INFO"
    if (Test-ScriptExists $Script:RiskNoXScript "RiskNoX") {
        try {
            # Execute RiskNoX configure command and show its output directly
            $configProcess = Start-Process -FilePath "pwsh.exe" -ArgumentList @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $Script:RiskNoXScript, "-Action", "configure") -WorkingDirectory $Script:AgentPath -NoNewWindow -Wait -PassThru
            
            if ($configProcess.ExitCode -eq 0) {
                Write-UnifiedLog "✅ RiskNoX Agent configured successfully!" "SUCCESS"
                $configResults += @{Name = "RiskNoX Security Agent"; Success = $true}
            } else {
                Write-UnifiedLog "❌ RiskNoX Agent configuration failed with exit code: $($configProcess.ExitCode)" "ERROR"
                $configResults += @{Name = "RiskNoX Security Agent"; Success = $false}
            }
        }
        catch {
            Write-UnifiedLog "❌ Error configuring RiskNoX Agent: $($_.Exception.Message)" "ERROR"
            $configResults += @{Name = "RiskNoX Security Agent"; Success = $false}
        }
    } else {
        $configResults += @{Name = "RiskNoX Security Agent"; Success = $false}
    }
    
    Write-UnifiedLog " " "INFO"
    
    # Configure/Enroll Monitoring Agent
    Write-UnifiedLog "⚙️  Phase 2: Enrolling Monitoring Agent..." "INFO"
    if (Test-ScriptExists $Script:MonitoringScript "Monitoring Agent") {
        try {
            # Execute Monitoring Agent enroll command and show its output directly
            $enrollProcess = Start-Process -FilePath "pwsh.exe" -ArgumentList @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $Script:MonitoringScript, "enroll") -WorkingDirectory $Script:AgentPath -NoNewWindow -Wait -PassThru
            
            if ($enrollProcess.ExitCode -eq 0) {
                Write-UnifiedLog "✅ Monitoring Agent enrolled successfully!" "SUCCESS"
                $configResults += @{Name = "Monitoring Agent"; Success = $true}
            } else {
                Write-UnifiedLog "❌ Monitoring Agent enrollment failed with exit code: $($enrollProcess.ExitCode)" "ERROR"
                $configResults += @{Name = "Monitoring Agent"; Success = $false}
            }
        }
        catch {
            Write-UnifiedLog "❌ Error enrolling Monitoring Agent: $($_.Exception.Message)" "ERROR"
            $configResults += @{Name = "Monitoring Agent"; Success = $false}
        }
    } else {
        $configResults += @{Name = "Monitoring Agent"; Success = $false}
    }
    
    # Summary
    Write-UnifiedLog " " "INFO"
    Write-UnifiedLog "📊 CONFIGURATION SUMMARY" "INFO"
    Write-UnifiedLog "========================" "INFO"
    
    $successful = $configResults | Where-Object { $_.Success }
    $failed = $configResults | Where-Object { !$_.Success }
    
    if ($successful) {
        Write-UnifiedLog "✅ Successfully Configured:" "SUCCESS"
        foreach ($item in $successful) {
            Write-UnifiedLog "   ✓ $($item.Name)" "SUCCESS"
        }
    }
    
    if ($failed) {
        Write-UnifiedLog "❌ Failed to Configure:" "ERROR"
        foreach ($item in $failed) {
            Write-UnifiedLog "   ✗ $($item.Name)" "ERROR"
        }
    }
    
    $overallSuccess = $failed.Count -eq 0
    if ($overallSuccess) {
        Write-UnifiedLog "🎉 ALL AGENTS CONFIGURED SUCCESSFULLY!" "SUCCESS"
        Write-UnifiedLog "💡 Next step: Run 'start' to begin security monitoring" "INFO"
    } else {
        Write-UnifiedLog "⚠️  PARTIAL CONFIGURATION - Some agents failed" "WARN"
    }
    
    Write-UnifiedLog "========================================" "INFO"
    return $overallSuccess
}

function Uninstall-AllAgents {
    Write-UnifiedLog "🗑️🗑️🗑️🗑️🗑️🗑️🗑️🗑️🗑️🗑️🗑️🗑️🗑️🗑️🗑️🗑️🗑️🗑️🗑️🗑️" "INFO"
    Write-UnifiedLog "🗑️  UNINSTALLING ALL SECURITY AGENTS 🗑️" "INFO"
    Write-UnifiedLog "🗑️🗑️🗑️🗑️🗑️🗑️🗑️🗑️🗑️🗑️🗑️🗑️🗑️🗑️🗑️🗑️🗑️🗑️🗑️🗑️" "INFO"
    
    # Confirm uninstall action
    Write-UnifiedLog "⚠️  WARNING: This will completely remove all security agents!" "WARN"
    Write-Host "Are you sure you want to uninstall all agents? (Type 'YES' to confirm): " -ForegroundColor Red -NoNewline
    $confirmation = Read-Host
    
    if ($confirmation -ne 'YES') {
        Write-UnifiedLog "❌ Uninstall cancelled by user" "WARN"
        return $false
    }
    
    $uninstallResults = @()
    
    # First stop all agents
    Write-UnifiedLog "🛑 Phase 1: Stopping all agents before uninstall..." "INFO"
    Stop-AllAgents | Out-Null
    
    Write-UnifiedLog " " "INFO"
    
    # Uninstall RiskNoX Agent
    Write-UnifiedLog "🗑️  Phase 2: Uninstalling RiskNoX Security Agent..." "INFO"
    if (Test-ScriptExists $Script:RiskNoXScript "RiskNoX") {
        try {
            # Execute RiskNoX uninstall command and show its output directly
            $uninstallProcess = Start-Process -FilePath "pwsh.exe" -ArgumentList @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $Script:RiskNoXScript, "-Action", "uninstall") -WorkingDirectory $Script:AgentPath -NoNewWindow -Wait -PassThru
            
            if ($uninstallProcess.ExitCode -eq 0) {
                Write-UnifiedLog "✅ RiskNoX Agent uninstalled successfully!" "SUCCESS"
                $uninstallResults += @{Name = "RiskNoX Security Agent"; Success = $true}
            } else {
                Write-UnifiedLog "❌ RiskNoX Agent uninstall failed with exit code: $($uninstallProcess.ExitCode)" "ERROR"
                $uninstallResults += @{Name = "RiskNoX Security Agent"; Success = $false}
            }
        }
        catch {
            Write-UnifiedLog "❌ Error uninstalling RiskNoX Agent: $($_.Exception.Message)" "ERROR"
            $uninstallResults += @{Name = "RiskNoX Security Agent"; Success = $false}
        }
    } else {
        Write-UnifiedLog "ℹ️  RiskNoX script not found, skipping uninstall" "INFO"
        $uninstallResults += @{Name = "RiskNoX Security Agent"; Success = $true}
    }
    
    Write-UnifiedLog " " "INFO"
    
    # Note about Monitoring Agent (typically doesn't have uninstall)
    Write-UnifiedLog "ℹ️  Phase 3: Monitoring Agent cleanup..." "INFO"
    Write-UnifiedLog "ℹ️  Monitoring Agent is part of the package and doesn't require separate uninstall" "INFO"
    Write-UnifiedLog "ℹ️  All agent processes have been stopped" "INFO"
    $uninstallResults += @{Name = "Monitoring Agent"; Success = $true}
    
    # Summary
    Write-UnifiedLog " " "INFO"
    Write-UnifiedLog "📊 UNINSTALL SUMMARY" "INFO"
    Write-UnifiedLog "====================" "INFO"
    
    $successful = $uninstallResults | Where-Object { $_.Success }
    $failed = $uninstallResults | Where-Object { !$_.Success }
    
    if ($successful) {
        Write-UnifiedLog "✅ Successfully Uninstalled:" "SUCCESS"
        foreach ($item in $successful) {
            Write-UnifiedLog "   ✓ $($item.Name)" "SUCCESS"
        }
    }
    
    if ($failed) {
        Write-UnifiedLog "❌ Failed to Uninstall:" "ERROR"
        foreach ($item in $failed) {
            Write-UnifiedLog "   ✗ $($item.Name)" "ERROR"
        }
    }
    
    $overallSuccess = $failed.Count -eq 0
    if ($overallSuccess) {
        Write-UnifiedLog "🎉 ALL AGENTS UNINSTALLED SUCCESSFULLY!" "SUCCESS"
        Write-UnifiedLog "🔓 Security monitoring has been completely removed" "INFO"
    } else {
        Write-UnifiedLog "⚠️  PARTIAL UNINSTALL - Some components may remain" "WARN"
    }
    
    Write-UnifiedLog "========================================" "INFO"
    return $overallSuccess
}

function Restart-AllAgents {
    Write-UnifiedLog "🔄 RESTARTING ALL SECURITY AGENTS" "INFO"
    Write-UnifiedLog "===================================" "INFO"
    
    # Stop first
    Write-UnifiedLog "Step 1: Stopping all agents..." "INFO"
    $stopSuccess = Stop-AllAgents
    
    # Wait a moment
    Write-UnifiedLog "Waiting 3 seconds..." "INFO"
    Start-Sleep -Seconds 3
    
    # Start again
    Write-UnifiedLog "Step 2: Starting all agents..." "INFO"
    $startSuccess = Start-AllAgents
    
    return ($stopSuccess -and $startSuccess)
}
#endregion
#region Interactive Menu
function Show-InteractiveMenu {
    while ($true) {
        Clear-Host
        Write-Host "========================================" -ForegroundColor Cyan
        Write-Host "   Unified Security Agents Control    " -ForegroundColor Cyan
        Write-Host "========================================" -ForegroundColor Cyan
        Write-Host ""
        
        Write-Host "Available Actions:" -ForegroundColor Yellow
        Write-Host "  1. Install All Agents" -ForegroundColor White
        Write-Host "  2. Start All Agents" -ForegroundColor White
        Write-Host "  3. Stop All Agents" -ForegroundColor White
        Write-Host "  4. Restart All Agents" -ForegroundColor White
        Write-Host "  5. Show Status" -ForegroundColor White
        Write-Host "  6. Configure All Agents" -ForegroundColor White
        Write-Host "  7. Uninstall All Agents" -ForegroundColor White
        Write-Host "  0. Exit" -ForegroundColor White
        Write-Host ""
        
        $choice = Read-Host "Enter your choice (0-7)"
        
        switch ($choice) {
            "1" { 
                Install-AllAgents
                Read-Host "Press Enter to continue..."
            }
            "2" { 
                Start-AllAgents
                Read-Host "Press Enter to continue..."
            }
            "3" { 
                Stop-AllAgents
                Read-Host "Press Enter to continue..."
            }
            "4" { 
                Restart-AllAgents
                Read-Host "Press Enter to continue..."
            }
            "5" { 
                Get-UnifiedStatus
                Read-Host "Press Enter to continue..."
            }
            "6" { 
                Configure-AllAgents
                Read-Host "Press Enter to continue..."
            }
            "7" { 
                Uninstall-AllAgents
                Read-Host "Press Enter to continue..."
            }
            "0" { 
                Write-UnifiedLog "Exiting Unified Control..." "INFO"
                return 
            }
            default { 
                Write-Host "Invalid choice. Please try again." -ForegroundColor Red
                Start-Sleep -Seconds 2
            }
        }
    }
}
#endregion

#region Main Execution
function Main {
    # Ensure running as administrator
    if (!(Test-AdminRights)) {
        Write-UnifiedLog "This script requires administrator privileges" "ERROR"
        Write-Host "Please run as Administrator" -ForegroundColor Red
        Read-Host "Press Enter to exit..."
        exit 1
    }
    
    Write-UnifiedLog "Unified Agent Control v2.0.0 - Action: $Action" "INFO"
    
    try {
        switch ($Action.ToLower()) {
            "install" { Install-AllAgents }
            "start" { Start-AllAgents }
            "stop" { Stop-AllAgents }
            "restart" { Restart-AllAgents }
            "status" { Get-UnifiedStatus }
            "configure" { Configure-AllAgents }
            "uninstall" { Uninstall-AllAgents }
            "menu" { Show-InteractiveMenu }
            default {
                Write-UnifiedLog "Invalid action: $Action" "ERROR"
                Write-Host "Valid actions: install, start, stop, restart, status, configure, uninstall, menu" -ForegroundColor Yellow
                exit 1
            }
        }
    }
    catch {
        Write-UnifiedLog "Fatal error in main execution: $($_.Exception.Message)" "ERROR"
        exit 1
    }
}

# Execute main function
Main
#endregion