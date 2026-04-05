#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Refresh credentials and environment variables for RiskNoX services
.DESCRIPTION
    Updates configuration securely and restarts the supervisor service
    Credentials are stored in Windows Credential Manager or environment variables
#>

param(
    [Parameter(Mandatory=$false)]
    [string]$ManagerUrl,
    
    [Parameter(Mandatory=$false)]
    [string]$AgentApiKey,
    
    [Parameter(Mandatory=$false)]
    [string]$ServiceName = "RiskNoXSupervisor",
    
    [switch]$Interactive
)

$ErrorActionPreference = "Stop"
$REPO_ROOT = Split-Path $PSScriptRoot -Parent
$CONFIG_DIR = Join-Path $REPO_ROOT "config"
$AGENT_CONFIG = Join-Path $CONFIG_DIR "agent_config.json"

function Write-CredLog {
    param([string]$Message, [string]$Level = "INFO")
    $colors = @{ INFO = "Cyan"; SUCCESS = "Green"; ERROR = "Red"; WARN = "Yellow" }
    Write-Host "[$Level] $Message" -ForegroundColor $colors[$Level]
}

function Get-SecureCredential {
    param(
        [string]$Target,
        [string]$Prompt
    )
    
    Write-Host ""
    Write-Host $Prompt -ForegroundColor Yellow
    $credential = Read-Host -AsSecureString
    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($credential)
    $value = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    
    return $value
}

function Save-ToCredentialManager {
    param(
        [string]$Target,
        [string]$Username,
        [string]$Password
    )
    
    try {
        # Use cmdkey to store credentials
        $null = cmdkey /add:$Target /user:$Username /pass:$Password
        Write-CredLog "Credential saved to Windows Credential Manager: $Target" "SUCCESS"
        return $true
    }
    catch {
        Write-CredLog "Failed to save credential: $_" "ERROR"
        return $false
    }
}

function Update-AgentConfig {
    param(
        [string]$ManagerUrl,
        [string]$ApiKey
    )
    
    try {
        # Load or create config
        $config = @{}
        if (Test-Path $AGENT_CONFIG) {
            $config = Get-Content $AGENT_CONFIG -Raw | ConvertFrom-Json -AsHashtable
        }
        
        # Update values
        if ($ManagerUrl) {
            $config['manager_url'] = $ManagerUrl
            Write-CredLog "Updated Manager URL" "SUCCESS"
        }
        
        if ($ApiKey) {
            # Store API key in credential manager
            Save-ToCredentialManager -Target "RiskNoX_AgentApiKey" -Username "agent" -Password $ApiKey
            $config['api_key_stored'] = $true
            Write-CredLog "API Key stored securely" "SUCCESS"
        }
        
        # Save config
        $config | ConvertTo-Json -Depth 10 | Set-Content $AGENT_CONFIG
        Write-CredLog "Configuration updated: $AGENT_CONFIG" "SUCCESS"
        
        return $true
    }
    catch {
        Write-CredLog "Failed to update configuration: $_" "ERROR"
        return $false
    }
}

function Update-EnvironmentVariables {
    param([hashtable]$Variables)
    
    try {
        foreach ($key in $Variables.Keys) {
            $value = $Variables[$key]
            [Environment]::SetEnvironmentVariable($key, $value, [EnvironmentVariableTarget]::Machine)
            Write-CredLog "Set environment variable: $key" "SUCCESS"
        }
        return $true
    }
    catch {
        Write-CredLog "Failed to update environment variables: $_" "ERROR"
        return $false
    }
}

function Restart-SupervisorService {
    param([string]$Name)
    
    try {
        $service = Get-Service -Name $Name -ErrorAction SilentlyContinue
        
        if (-not $service) {
            Write-CredLog "Service not found: $Name" "WARN"
            Write-CredLog "Changes will take effect on next service start" "INFO"
            return $true
        }
        
        Write-CredLog "Restarting service: $Name" "INFO"
        
        if ($service.Status -eq 'Running') {
            Stop-Service -Name $Name -Force
            Start-Sleep -Seconds 5
        }
        
        Start-Service -Name $Name
        Start-Sleep -Seconds 3
        
        $service = Get-Service -Name $Name
        if ($service.Status -eq 'Running') {
            Write-CredLog "Service restarted successfully" "SUCCESS"
            return $true
        }
        else {
            Write-CredLog "Service failed to start" "ERROR"
            return $false
        }
    }
    catch {
        Write-CredLog "Failed to restart service: $_" "ERROR"
        return $false
    }
}

function Show-InteractiveMenu {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host " RiskNoX Credential Refresh Tool" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "What would you like to update?" -ForegroundColor Yellow
    Write-Host "  1. Manager URL and API Key" -ForegroundColor White
    Write-Host "  2. Manager URL only" -ForegroundColor White
    Write-Host "  3. API Key only" -ForegroundColor White
    Write-Host "  4. Environment Variables" -ForegroundColor White
    Write-Host "  0. Exit" -ForegroundColor White
    Write-Host ""
    
    $choice = Read-Host "Enter choice (0-4)"
    
    $managerUrl = $null
    $apiKey = $null
    $envVars = @{}
    
    switch ($choice) {
        "1" {
            $managerUrl = Read-Host "Enter Manager URL (e.g., https://manager.example.com)"
            $apiKey = Get-SecureCredential -Target "RiskNoX_AgentApiKey" -Prompt "Enter Agent API Key"
        }
        "2" {
            $managerUrl = Read-Host "Enter Manager URL (e.g., https://manager.example.com)"
        }
        "3" {
            $apiKey = Get-SecureCredential -Target "RiskNoX_AgentApiKey" -Prompt "Enter Agent API Key"
        }
        "4" {
            Write-Host ""
            Write-Host "Enter environment variables (format: KEY=VALUE, empty to finish)" -ForegroundColor Yellow
            while ($true) {
                $entry = Read-Host "Variable"
                if ([string]::IsNullOrWhiteSpace($entry)) { break }
                
                $parts = $entry -split '=', 2
                if ($parts.Count -eq 2) {
                    $envVars[$parts[0].Trim()] = $parts[1].Trim()
                }
            }
        }
        "0" {
            Write-CredLog "Cancelled by user" "INFO"
            exit 0
        }
        default {
            Write-CredLog "Invalid choice" "ERROR"
            exit 1
        }
    }
    
    return @{
        ManagerUrl = $managerUrl
        ApiKey = $apiKey
        EnvVars = $envVars
    }
}

function Main {
    Write-CredLog "RiskNoX Credential Refresh Tool" "INFO"
    Write-CredLog "===============================" "INFO"
    
    $updates = @{
        ManagerUrl = $ManagerUrl
        ApiKey = $AgentApiKey
        EnvVars = @{}
    }
    
    # Interactive mode
    if ($Interactive -or (-not $ManagerUrl -and -not $AgentApiKey)) {
        $updates = Show-InteractiveMenu
    }
    
    # Apply updates
    $success = $true
    
    if ($updates.ManagerUrl -or $updates.ApiKey) {
        if (-not (Update-AgentConfig -ManagerUrl $updates.ManagerUrl -ApiKey $updates.ApiKey)) {
            $success = $false
        }
    }
    
    if ($updates.EnvVars.Count -gt 0) {
        if (-not (Update-EnvironmentVariables -Variables $updates.EnvVars)) {
            $success = $false
        }
    }
    
    if (-not $success) {
        Write-CredLog "Some updates failed" "ERROR"
        exit 1
    }
    
    # Restart service to apply changes
    Write-Host ""
    $restart = Read-Host "Restart $ServiceName service to apply changes? (y/n)"
    if ($restart -eq 'y' -or $restart -eq 'Y') {
        Restart-SupervisorService -Name $ServiceName
    }
    else {
        Write-CredLog "Service not restarted. Changes will apply on next service start" "WARN"
    }
    
    Write-Host ""
    Write-CredLog "Credential refresh completed" "SUCCESS"
    exit 0
}

Main
