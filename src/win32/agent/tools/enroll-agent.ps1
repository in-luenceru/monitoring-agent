#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Enroll Monitoring Agent with Manager
    
.DESCRIPTION
    Enrolls the Wazuh-based monitoring agent with a central manager server.
    Handles client key registration and manager IP configuration.
    
.PARAMETER ManagerIP
    IP address of the Wazuh manager (e.g., "10.0.1.100")
    
.PARAMETER ClientKey
    Client authentication key (plain text or base64 encoded)
    
.PARAMETER Interactive
    Run in interactive mode (prompts for inputs)
    
.EXAMPLE
    .\enroll-agent.ps1 -Interactive
    .\enroll-agent.ps1 -ManagerIP "10.0.1.100" -ClientKey "001 agent01 10.0.1.100 abc123..."
    
.NOTES
    Requires Administrator privileges
    Must be run BEFORE starting the supervisor service
#>

param(
    [string]$ManagerIP,
    [string]$ClientKey,
    [switch]$Interactive
)

$ErrorActionPreference = "Stop"
$AgentRoot = Split-Path $PSScriptRoot -Parent

# File paths
$OssecConf = Join-Path $AgentRoot "ossec.conf"
$ClientKeys = Join-Path $AgentRoot "client.keys"
$ClientKeysBackup = Join-Path $AgentRoot "client.keys.backup_$(Get-Date -Format 'yyyyMMdd_HHmmss')"

# Color output functions
function Write-Info { param([string]$msg) Write-Host "[INFO] $msg" -ForegroundColor Cyan }
function Write-Success { param([string]$msg) Write-Host "[SUCCESS] $msg" -ForegroundColor Green }
function Write-Warning { param([string]$msg) Write-Host "[WARN] $msg" -ForegroundColor Yellow }
function Write-ErrorMsg { param([string]$msg) Write-Host "[ERROR] $msg" -ForegroundColor Red }

function Test-AdminRights {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-Base64String {
    param([string]$String)
    try {
        $null = [Convert]::FromBase64String($String)
        return $true
    }
    catch {
        return $false
    }
}

function Get-SecureInput {
    param([string]$Prompt)
    Write-Host "$Prompt" -NoNewline -ForegroundColor Yellow
    return Read-Host
}

function Backup-FileIfExists {
    param([string]$FilePath)
    if (Test-Path $FilePath) {
        $backupPath = "$FilePath.backup_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
        Copy-Item -Path $FilePath -Destination $backupPath -Force
        Write-Info "Backed up existing file to: $backupPath"
    }
}

# Check admin rights
if (!(Test-AdminRights)) {
    Write-ErrorMsg "This script requires Administrator privileges"
    exit 1
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Monitoring Agent Enrollment" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Interactive mode
if ($Interactive -or (-not $ManagerIP) -or (-not $ClientKey)) {
    Write-Info "Running in interactive mode..."
    Write-Host ""
    
    if (-not $ManagerIP) {
        $ManagerIP = Get-SecureInput "Enter Manager IP address (e.g., 10.0.1.100): "
        if ([string]::IsNullOrWhiteSpace($ManagerIP)) {
            Write-ErrorMsg "Manager IP is required"
            exit 1
        }
    }
    
    if (-not $ClientKey) {
        Write-Host ""
        Write-Info "Client key format: '001 agent-name manager-ip key-hash'"
        Write-Info "Example: 001 agent01 10.0.1.100 abc123def456..."
        Write-Host ""
        $ClientKey = Get-SecureInput "Enter Client Key: "
        if ([string]::IsNullOrWhiteSpace($ClientKey)) {
            Write-ErrorMsg "Client key is required"
            exit 1
        }
    }
}

# Validate inputs
Write-Info "Validating inputs..."

# Validate Manager IP
try {
    $ipAddress = [System.Net.IPAddress]::Parse($ManagerIP)
    Write-Success "Manager IP valid: $ManagerIP"
}
catch {
    Write-ErrorMsg "Invalid Manager IP address: $ManagerIP"
    exit 1
}

# Validate Client Key format
$clientKeyTrimmed = $ClientKey.Trim()

# Check if base64 encoded
if (Test-Base64String $clientKeyTrimmed) {
    Write-Info "Client key appears to be base64 encoded"
    try {
        $decodedBytes = [Convert]::FromBase64String($clientKeyTrimmed)
        $decodedKey = [System.Text.Encoding]::UTF8.GetString($decodedBytes)
        Write-Success "Client key decoded successfully"
        $clientKeyTrimmed = $decodedKey
    }
    catch {
        Write-ErrorMsg "Failed to decode base64 client key"
        exit 1
    }
}

# Validate client key format: "ID NAME IP KEY"
if ($clientKeyTrimmed -notmatch '^\d+\s+\S+\s+\S+\s+\S+') {
    Write-ErrorMsg "Invalid client key format"
    Write-Info "Expected format: '001 agent-name manager-ip key-hash'"
    Write-Info "Received: $clientKeyTrimmed"
    exit 1
}

Write-Success "Client key format valid"

# Step 1: Update client.keys
Write-Host ""
Write-Info "Step 1/3: Writing client.keys file..."

if (Test-Path $ClientKeys) {
    Backup-FileIfExists $ClientKeys
}

try {
    # Ensure proper encoding and line ending
    $clientKeyTrimmed | Set-Content -Path $ClientKeys -Encoding ASCII -NoNewline
    # Add newline at end
    Add-Content -Path $ClientKeys -Value "" -Encoding ASCII
    
    Write-Success "client.keys written successfully"
    Write-Info "Location: $ClientKeys"
}
catch {
    Write-ErrorMsg "Failed to write client.keys: $_"
    exit 1
}

# Step 2: Update ossec.conf with Manager IP
Write-Host ""
Write-Info "Step 2/3: Updating ossec.conf with manager IP..."

if (!(Test-Path $OssecConf)) {
    Write-ErrorMsg "ossec.conf not found: $OssecConf"
    Write-Info "Ensure monitoring-agent files are present in: $AgentRoot"
    exit 1
}

Backup-FileIfExists $OssecConf

try {
    # Read ossec.conf
    [xml]$ossecXml = Get-Content $OssecConf
    
    # Find and update manager address
    $clientNode = $ossecXml.ossec_config.client
    if ($clientNode) {
        $serverNode = $clientNode.server
        if ($serverNode) {
            # Update existing server address
            if ($serverNode.address) {
                $oldAddress = $serverNode.address
                $serverNode.address = $ManagerIP
                Write-Success "Updated manager address: $oldAddress → $ManagerIP"
            } else {
                # Add address element
                $addressElement = $ossecXml.CreateElement("address")
                $addressElement.InnerText = $ManagerIP
                $serverNode.AppendChild($addressElement) | Out-Null
                Write-Success "Added manager address: $ManagerIP"
            }
        } else {
            Write-ErrorMsg "No <server> node found in ossec.conf"
            exit 1
        }
    } else {
        Write-ErrorMsg "No <client> node found in ossec.conf"
        exit 1
    }
    
    # Save updated XML
    $ossecXml.Save($OssecConf)
    Write-Success "ossec.conf updated successfully"
}
catch {
    Write-ErrorMsg "Failed to update ossec.conf: $_"
    exit 1
}

# Step 3: Verify enrollment
Write-Host ""
Write-Info "Step 3/3: Verifying enrollment..."

$clientKeysContent = Get-Content $ClientKeys -Raw
$clientKeysLines = $clientKeysContent.Trim() -split "`n"

if ($clientKeysLines.Count -gt 0 -and $clientKeysLines[0].Length -gt 0) {
    Write-Success "client.keys contains: $($clientKeysLines[0].Substring(0, [Math]::Min(50, $clientKeysLines[0].Length)))..."
} else {
    Write-ErrorMsg "client.keys appears empty"
    exit 1
}

# Check ossec.conf
[xml]$ossecCheck = Get-Content $OssecConf
$currentManager = $ossecCheck.ossec_config.client.server.address
if ($currentManager -eq $ManagerIP) {
    Write-Success "ossec.conf manager address: $currentManager"
} else {
    Write-Warning "ossec.conf manager mismatch: expected $ManagerIP, got $currentManager"
}

# Final summary
Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "  ✅ ENROLLMENT COMPLETE!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Success "Agent enrolled successfully"
Write-Info "Manager IP: $ManagerIP"
Write-Info "Client Keys: $ClientKeys"
Write-Info "Configuration: $OssecConf"
Write-Host ""
Write-Info "Next steps:"
Write-Info "  1. Ensure supervisor is installed: .\tools\install_service.ps1"
Write-Info "  2. Start the service:              .\tools\start.ps1"
Write-Info "  3. Check agent status:             .\tools\status.ps1"
Write-Host ""
Write-Warning "Important: The monitoring agent will connect to manager on next start"
Write-Info "If supervisor is already running, restart it:"
Write-Info "  .\tools\restart.ps1"
Write-Host ""
