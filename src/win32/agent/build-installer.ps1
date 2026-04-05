#Requires -Version 5.1

<#
.SYNOPSIS
    Professional build script for RiskNoX Monitoring Agent installer

.DESCRIPTION
    This script builds a Windows installer for the RiskNoX Monitoring Agent using NSIS.
    It includes comprehensive validation, digital signing capabilities, and detailed
    build reporting with Wazuh-style professional output.

.PARAMETER ValidationOnly
    Only run validation checks without building

.PARAMETER SkipValidation
    Skip validation and build directly (not recommended)

.PARAMETER Sign
    Attempt to digitally sign the installer (requires code signing certificate)

.PARAMETER Detailed
    Show detailed output including file listings and verbose information

.PARAMETER OutputPath
    Specify custom output path for the installer (default: .\output\)

.EXAMPLE
    .\build-installer.ps1
    Standard build with validation

.EXAMPLE
    .\build-installer.ps1 -Detailed -Sign
    Detailed build with digital signing

.EXAMPLE
    .\build-installer.ps1 -ValidationOnly
    Only run validation checks
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [switch]$ValidationOnly,
    
    [Parameter(Mandatory=$false)]
    [switch]$SkipValidation,
    
    [Parameter(Mandatory=$false)]
    [switch]$Sign,
    
    [Parameter(Mandatory=$false)]
    [switch]$Detailed,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = ".\output\"
)

# Color output functions for professional presentation
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

# Global variables
$script:BuildStartTime = Get-Date
$script:TotalSteps = 7
$script:CurrentStep = 0
$script:BuildResult = @{
    Success = $false
    InstallerPath = ""
    InstallerSize = 0
    BuildTime = 0
    SigningResult = "Not Attempted"
    ValidationResult = "Not Run"
    Errors = @()
    Warnings = @()
}

function Show-Step {
    param([string]$StepName)
    $script:CurrentStep++
    Write-Host ""
    Write-Host "[$script:CurrentStep/$script:TotalSteps] $StepName" -ForegroundColor Yellow
    Write-Host ("─" * 50) -ForegroundColor Gray
}

function Test-NSISInstallation {
    Show-Step "Checking NSIS Installation"
    
    # Common NSIS installation paths
    $nsisLocations = @(
        "${env:ProgramFiles}\NSIS\makensis.exe",
        "${env:ProgramFiles(x86)}\NSIS\makensis.exe",
        "$env:LOCALAPPDATA\NSIS\makensis.exe",
        "C:\NSIS\makensis.exe"
    )
    
    $nsisPath = $null
    foreach ($location in $nsisLocations) {
        if (Test-Path $location) {
            $nsisPath = $location
            break
        }
    }
    
    if ($nsisPath) {
        try {
            $version = & $nsisPath /VERSION 2>$null
            Write-Success "NSIS found at: $nsisPath"
            Write-Info "Version: $version"
            
            # Check for required plugins
            $nsisDir = Split-Path $nsisPath -Parent
            $pluginDir = Join-Path $nsisDir "Plugins"
            
            $requiredPlugins = @("SimpleSC.dll", "nsProcess.dll", "AccessControl.dll")
            $missingPlugins = @()
            
            foreach ($plugin in $requiredPlugins) {
                $x86Plugin = Join-Path $pluginDir "x86-ansi\$plugin"
                $x64Plugin = Join-Path $pluginDir "x86-unicode\$plugin"
                
                if (!(Test-Path $x86Plugin) -and !(Test-Path $x64Plugin)) {
                    $missingPlugins += $plugin
                }
            }
            
            if ($missingPlugins.Count -gt 0) {
                Write-Warning "Missing NSIS plugins: $($missingPlugins -join ', ')"
                Write-Info "Download from: https://nsis.sourceforge.io/Category:Plugins"
                $script:BuildResult.Warnings += "Missing NSIS plugins: $($missingPlugins -join ', ')"
            } else {
                Write-Success "All required NSIS plugins are available"
            }
            
            return $nsisPath
        } catch {
            Write-Error "NSIS found but not working properly: $($_.Exception.Message)"
            return $null
        }
    } else {
        Write-Error "NSIS not found in standard installation locations"
        Write-Info "Download NSIS from: https://nsis.sourceforge.io/Download"
        Write-Info "Install to: ${env:ProgramFiles}\NSIS\"
        return $null
    }
}

function Invoke-Validation {
    Show-Step "Running Comprehensive Validation"
    
    if (Test-Path ".\validate-installer-files.ps1") {
        try {
            $validationArgs = @()
            if ($Detailed) { $validationArgs += "-Detailed" }
            
            Write-Info "Executing validation script..."
            $validationResult = & ".\validate-installer-files.ps1" @validationArgs
            $lastExitCode = $LASTEXITCODE
            
            if ($lastExitCode -eq 0) {
                Write-Success "Validation completed successfully"
                $script:BuildResult.ValidationResult = "Passed"
                return $true
            } else {
                Write-Error "Validation failed with exit code: $lastExitCode"
                $script:BuildResult.ValidationResult = "Failed"
                $script:BuildResult.Errors += "Validation failed"
                return $false
            }
        } catch {
            Write-Error "Error running validation: $($_.Exception.Message)"
            $script:BuildResult.ValidationResult = "Error"
            $script:BuildResult.Errors += "Validation error: $($_.Exception.Message)"
            return $false
        }
    } else {
        Write-Warning "Validation script not found - skipping detailed validation"
        $script:BuildResult.ValidationResult = "Skipped"
        $script:BuildResult.Warnings += "Validation script not found"
        
        # Basic validation
        if (!(Test-Path "RiskNoX-Installer.nsi")) {
            Write-Error "RiskNoX-Installer.nsi not found"
            $script:BuildResult.Errors += "NSI script not found"
            return $false
        }
        
        Write-Success "Basic validation passed"
        return $true
    }
}

function Prepare-OutputDirectory {
    Show-Step "Preparing Output Directory"
    
    try {
        if (Test-Path $OutputPath) {
            Write-Info "Output directory exists: $OutputPath"
            
            # Clean old installers
            $oldInstallers = Get-ChildItem $OutputPath -Filter "*.exe" -ErrorAction SilentlyContinue
            if ($oldInstallers.Count -gt 0) {
                Write-Info "Removing $($oldInstallers.Count) old installer files..."
                $oldInstallers | Remove-Item -Force
                Write-Success "Old installers removed"
            }
        } else {
            Write-Info "Creating output directory: $OutputPath"
            New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
            Write-Success "Output directory created"
        }
        
        # Test write permissions
        $testFile = Join-Path $OutputPath "test-write.tmp"
        try {
            "test" | Out-File $testFile
            Remove-Item $testFile -Force
            Write-Success "Output directory is writable"
            return $true
        } catch {
            Write-Error "Cannot write to output directory: $($_.Exception.Message)"
            $script:BuildResult.Errors += "Output directory not writable"
            return $false
        }
    } catch {
        Write-Error "Error preparing output directory: $($_.Exception.Message)"
        $script:BuildResult.Errors += "Output directory preparation failed"
        return $false
    }
}

function Get-InstallerVersion {
    try {
        if (Test-Path "VERSION.json") {
            $versionInfo = Get-Content "VERSION.json" | ConvertFrom-Json
            return $versionInfo.version
        } elseif (Test-Path "RiskNoX-Installer.nsi") {
            $nsiContent = Get-Content "RiskNoX-Installer.nsi"
            $versionLine = $nsiContent | Where-Object { $_ -match '!define\s+PRODUCT_VERSION\s+"([^"]+)"' }
            if ($versionLine) {
                return $Matches[1]
            }
        }
        return "1.0.0"
    } catch {
        return "1.0.0"
    }
}

function Invoke-NSISBuild {
    param([string]$NSISPath)
    
    Show-Step "Building Installer with NSIS"
    
    $version = Get-InstallerVersion
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $installerName = "RiskNoX-Agent-$version-$timestamp.exe"
    $installerPath = Join-Path $OutputPath $installerName
    
    Write-Info "Building installer: $installerName"
    Write-Info "Version: $version"
    Write-Info "Timestamp: $timestamp"
    
    try {
        # NSIS command line arguments
        $nsisArgs = @()
        $nsisArgs += "/DOUTPUT_FILE=$installerPath"
        $nsisArgs += "/DPRODUCT_VERSION=$version"
        if ($Detailed) {
            $nsisArgs += "/V4"  # Verbose output
        } else {
            $nsisArgs += "/V2"  # Normal output
        }
        $nsisArgs += "RiskNoX-Installer.nsi"
        
        Write-Info "Executing NSIS with arguments: $($nsisArgs -join ' ')"
        
        # Execute NSIS
        $buildOutput = & $NSISPath @nsisArgs 2>&1
        $buildExitCode = $LASTEXITCODE
        
        if ($Detailed) {
            Write-Host ""
            Write-Host "NSIS Build Output:" -ForegroundColor Cyan
            Write-Host "─────────────────" -ForegroundColor Gray
            $buildOutput | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }
            Write-Host ""
        }
        
        if ($buildExitCode -eq 0 -and (Test-Path $installerPath)) {
            $installerSize = (Get-Item $installerPath).Length
            $installerSizeStr = if ($installerSize -gt 1MB) { "{0:N1} MB" -f ($installerSize/1MB) }
                               elseif ($installerSize -gt 1KB) { "{0:N1} KB" -f ($installerSize/1KB) }
                               else { "$installerSize bytes" }
            
            Write-Success "Installer built successfully"
            Write-Info "Location: $installerPath"
            Write-Info "Size: $installerSizeStr"
            
            $script:BuildResult.Success = $true
            $script:BuildResult.InstallerPath = $installerPath
            $script:BuildResult.InstallerSize = $installerSize
            
            return $installerPath
        } else {
            Write-Error "NSIS build failed with exit code: $buildExitCode"
            if (!$Detailed -and $buildOutput) {
                Write-Host ""
                Write-Host "Build Output (last 10 lines):" -ForegroundColor Red
                $buildOutput | Select-Object -Last 10 | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }
            }
            
            $script:BuildResult.Errors += "NSIS build failed with exit code: $buildExitCode"
            return $null
        }
    } catch {
        Write-Error "Error executing NSIS: $($_.Exception.Message)"
        $script:BuildResult.Errors += "NSIS execution error: $($_.Exception.Message)"
        return $null
    }
}

function Invoke-CodeSigning {
    param([string]$InstallerPath)
    
    Show-Step "Digital Code Signing"
    
    if (!$Sign) {
        Write-Info "Code signing skipped (use -Sign to enable)"
        $script:BuildResult.SigningResult = "Skipped"
        return $true
    }
    
    # Look for signing certificate
    $certs = Get-ChildItem Cert:\CurrentUser\My | Where-Object { 
        $_.HasPrivateKey -and 
        $_.Extensions["2.5.29.37"].EnhancedKeyUsages -match "Code Signing" 
    }
    
    if ($certs.Count -eq 0) {
        $certs = Get-ChildItem Cert:\LocalMachine\My | Where-Object { 
            $_.HasPrivateKey -and 
            $_.Extensions["2.5.29.37"].EnhancedKeyUsages -match "Code Signing" 
        }
    }
    
    if ($certs.Count -eq 0) {
        Write-Warning "No code signing certificate found"
        Write-Info "To enable signing, install a code signing certificate"
        $script:BuildResult.SigningResult = "No Certificate"
        $script:BuildResult.Warnings += "Code signing certificate not found"
        return $true
    }
    
    $cert = $certs[0]
    Write-Info "Using certificate: $($cert.Subject)"
    Write-Info "Thumbprint: $($cert.Thumbprint)"
    
    try {
        # Use signtool.exe if available
        $signTool = Get-Command signtool.exe -ErrorAction SilentlyContinue
        if ($signTool) {
            Write-Info "Signing with signtool.exe..."
            $signArgs = @(
                "sign",
                "/sha1", $cert.Thumbprint,
                "/t", "http://timestamp.digicert.com",
                "/d", "RiskNoX Monitoring Agent",
                "/du", "https://risknox.com",
                $InstallerPath
            )
            
            $signResult = & signtool.exe @signArgs 2>&1
            $signExitCode = $LASTEXITCODE
            
            if ($signExitCode -eq 0) {
                Write-Success "Installer signed successfully"
                $script:BuildResult.SigningResult = "Success"
            } else {
                Write-Warning "Signing failed: $signResult"
                $script:BuildResult.SigningResult = "Failed"
                $script:BuildResult.Warnings += "Code signing failed"
            }
        } else {
            Write-Warning "signtool.exe not found - skipping digital signing"
            Write-Info "Install Windows SDK to enable code signing"
            $script:BuildResult.SigningResult = "Tool Not Found"
            $script:BuildResult.Warnings += "signtool.exe not found"
        }
        
        return $true
    } catch {
        Write-Warning "Error during signing: $($_.Exception.Message)"
        $script:BuildResult.SigningResult = "Error"
        $script:BuildResult.Warnings += "Signing error: $($_.Exception.Message)"
        return $true
    }
}

function Test-InstallerBasic {
    param([string]$InstallerPath)
    
    Show-Step "Basic Installer Testing"
    
    if (!(Test-Path $InstallerPath)) {
        Write-Error "Installer file not found for testing"
        return $false
    }
    
    try {
        # Check file signature
        $signature = Get-AuthenticodeSignature $InstallerPath
        if ($signature.Status -eq "Valid") {
            Write-Success "Installer is digitally signed and valid"
        } elseif ($signature.Status -eq "NotSigned") {
            Write-Info "Installer is not digitally signed"
        } else {
            Write-Warning "Installer signature status: $($signature.Status)"
        }
        
        # Check if it's a valid PE file
        $fileBytes = [System.IO.File]::ReadAllBytes($InstallerPath)
        if ($fileBytes.Length -gt 64 -and $fileBytes[0] -eq 0x4D -and $fileBytes[1] -eq 0x5A) {
            Write-Success "Installer is a valid executable file"
        } else {
            Write-Error "Installer does not appear to be a valid executable"
            return $false
        }
        
        # Test basic execution (help mode)
        Write-Info "Testing installer help command..."
        try {
            $helpOutput = & $InstallerPath /? 2>&1
            if ($LASTEXITCODE -eq 0 -or $helpOutput -match "Usage:" -or $helpOutput -match "Silent") {
                Write-Success "Installer responds to command line options"
            } else {
                Write-Warning "Installer may have issues with command line interface"
            }
        } catch {
            Write-Warning "Could not test installer command line interface"
        }
        
        Write-Success "Basic installer tests completed"
        return $true
    } catch {
        Write-Error "Error testing installer: $($_.Exception.Message)"
        $script:BuildResult.Errors += "Installer testing failed"
        return $false
    }
}

function Show-BuildSummary {
    $buildEndTime = Get-Date
    $script:BuildResult.BuildTime = ($buildEndTime - $script:BuildStartTime).TotalSeconds
    
    Write-Header "Build Summary Report"
    
    Write-Host ""
    Write-Host "Build Information:" -ForegroundColor Cyan
    Write-Host "  Start Time: $($script:BuildStartTime.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor White
    Write-Host "  End Time: $($buildEndTime.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor White
    Write-Host "  Duration: $([math]::Round($script:BuildResult.BuildTime, 1)) seconds" -ForegroundColor White
    
    Write-Host ""
    Write-Host "Results:" -ForegroundColor Cyan
    Write-Host "  Build Status: $(if ($script:BuildResult.Success) { 'SUCCESS' } else { 'FAILED' })" -ForegroundColor $(if ($script:BuildResult.Success) { 'Green' } else { 'Red' })
    Write-Host "  Validation: $($script:BuildResult.ValidationResult)" -ForegroundColor White
    Write-Host "  Signing: $($script:BuildResult.SigningResult)" -ForegroundColor White
    
    if ($script:BuildResult.Success) {
        $sizeStr = if ($script:BuildResult.InstallerSize -gt 1MB) { "{0:N1} MB" -f ($script:BuildResult.InstallerSize/1MB) }
                   elseif ($script:BuildResult.InstallerSize -gt 1KB) { "{0:N1} KB" -f ($script:BuildResult.InstallerSize/1KB) }
                   else { "$($script:BuildResult.InstallerSize) bytes" }
        
        Write-Host ""
        Write-Host "Installer Details:" -ForegroundColor Cyan
        Write-Host "  File Path: $($script:BuildResult.InstallerPath)" -ForegroundColor White
        Write-Host "  File Size: $sizeStr" -ForegroundColor White
        
        $version = Get-InstallerVersion
        Write-Host "  Version: $version" -ForegroundColor White
    }
    
    if ($script:BuildResult.Warnings.Count -gt 0) {
        Write-Host ""
        Write-Host "Warnings ($($script:BuildResult.Warnings.Count)):" -ForegroundColor Yellow
        foreach ($warning in $script:BuildResult.Warnings) {
            Write-Host "  ⚠ $warning" -ForegroundColor Yellow
        }
    }
    
    if ($script:BuildResult.Errors.Count -gt 0) {
        Write-Host ""
        Write-Host "Errors ($($script:BuildResult.Errors.Count)):" -ForegroundColor Red
        foreach ($error in $script:BuildResult.Errors) {
            Write-Host "  ✗ $error" -ForegroundColor Red
        }
    }
    
    Write-Host ""
    if ($script:BuildResult.Success) {
        Write-Host "🎉 BUILD COMPLETED SUCCESSFULLY!" -ForegroundColor Green
        Write-Host ""
        Write-Info "Next steps:"
        Write-Host "  1. Test installer on clean Windows system" -ForegroundColor Green
        Write-Host "  2. Verify service installation and startup" -ForegroundColor Green
        Write-Host "  3. Test monitoring functionality" -ForegroundColor Green
        Write-Host "  4. Deploy to target systems" -ForegroundColor Green
        Write-Host ""
        Write-Info "Installation command:"
        Write-Host "  $($script:BuildResult.InstallerPath) /S" -ForegroundColor Yellow
    } else {
        Write-Host "❌ BUILD FAILED!" -ForegroundColor Red
        Write-Host "Please fix the errors above and try again." -ForegroundColor Red
    }
    
    Write-Host ""
}

# Main build process
try {
    Write-Host ""
    Write-Host "╔═══════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║                                                           ║" -ForegroundColor Cyan
    Write-Host "║     RiskNoX Monitoring Agent - Professional Installer     ║" -ForegroundColor Cyan
    Write-Host "║                        Build System                       ║" -ForegroundColor Cyan
    Write-Host "║                                                           ║" -ForegroundColor Cyan
    Write-Host "╚═══════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    
    # Step 1: Check NSIS
    $nsisPath = Test-NSISInstallation
    if (!$nsisPath) {
        $script:BuildResult.Errors += "NSIS not found or not working"
        Show-BuildSummary
        exit 1
    }
    
    # Step 2: Run validation (unless skipped)
    if (!$SkipValidation) {
        $validationPassed = Invoke-Validation
        if (!$validationPassed -and !$ValidationOnly) {
            Write-Error "Validation failed - stopping build"
            Show-BuildSummary
            exit 1
        }
    } else {
        Write-Warning "Validation skipped as requested"
        $script:BuildResult.ValidationResult = "Skipped"
    }
    
    # Stop here if validation only
    if ($ValidationOnly) {
        Write-Info "Validation-only mode completed"
        Show-BuildSummary
        exit $(if ($validationPassed) { 0 } else { 1 })
    }
    
    # Step 3: Prepare output
    $outputReady = Prepare-OutputDirectory
    if (!$outputReady) {
        Show-BuildSummary
        exit 1
    }
    
    # Step 4: Build installer
    $installerPath = Invoke-NSISBuild $nsisPath
    if (!$installerPath) {
        Show-BuildSummary
        exit 1
    }
    
    # Step 5: Code signing
    Invoke-CodeSigning $installerPath
    
    # Step 6: Basic testing
    Test-InstallerBasic $installerPath
    
    # Step 7: Show summary
    Show-BuildSummary
    
    exit $(if ($script:BuildResult.Success) { 0 } else { 1 })
}
catch {
    Write-Host ""
    Write-Error "UNEXPECTED BUILD ERROR: $($_.Exception.Message)"
    Write-Host ""
    Write-Host "Stack Trace:" -ForegroundColor Red
    Write-Host $_.ScriptStackTrace -ForegroundColor Red
    
    $script:BuildResult.Errors += "Unexpected error: $($_.Exception.Message)"
    Show-BuildSummary
    exit 1
}
    Write-Host "║                                                           ║" -ForegroundColor Cyan
    Write-Host "╚═══════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
}

# Find NSIS installation
function Find-NSIS {
    Write-Verbose "Searching for NSIS installation..."
    
    $nsisLocations = @(
        "${env:ProgramFiles(x86)}\NSIS\makensis.exe",
        "${env:ProgramFiles}\NSIS\makensis.exe",
        "C:\Program Files (x86)\NSIS\makensis.exe",
        "C:\Program Files\NSIS\makensis.exe"
    )
    
    foreach ($location in $nsisLocations) {
        if (Test-Path $location) {
            Write-Verbose "Found NSIS at: $location"
            return $location
        }
    }
    
    return $null
}

# Check required files
function Test-RequiredFiles {
    Write-Info "Checking required files..."
    
    $requiredFiles = @(
        # Core executables
        "monitoring-agent.exe",
        "backend_server.py",
        "service_control_backend.py",
        "agent_poll.py",
        "agent-auth.exe",
        "manage_agents.exe",
        
        # PowerShell scripts
        "RiskNoXServiceControl.ps1",
        "UnifiedAgentControl.ps1",
        "RiskNoX-Control.ps1",
        "MonitoringAgentControl.ps1",
        
        # DLL files
        "dbsync.dll",
        "libfimdb.dll",
        "libwazuhext.dll",
        "libwazuhshared.dll",
        "syscollector.dll",
        "sysinfo.dll",
        
        # Configuration files
        "ossec.conf",
        "internal_options.conf",
        "VERSION.json",
        "wpk_root.pem",
        
        # Critical tools
        "tools\nssm\win64\nssm.exe",
        "dist\supervisor.exe"
    )
    
    $missingFiles = @()
    $foundFiles = 0
    
    foreach ($file in $requiredFiles) {
        if (Test-Path $file) {
            $foundFiles++
            Write-Verbose "✓ Found: $file"
        } else {
            $missingFiles += $file
            Write-Verbose "✗ Missing: $file"
        }
    }
    
    Write-Info "Found $foundFiles of $($requiredFiles.Count) required files"
    
    if ($missingFiles.Count -gt 0) {
        Write-Warning "Missing required files:"
        foreach ($file in $missingFiles) {
            Write-Host "    - $file" -ForegroundColor Red
        }
        return $false
    }
    
    Write-Success "All required files found"
    return $true
}

# Check optional directories and files
function Test-OptionalComponents {
    Write-Info "Checking optional components..."
    
    $optionalComponents = @{
        "active-response" = "Active Response System"
        "config" = "Configuration System"
        "queue" = "Message Queue System"
        "shared" = "Shared Resources"
        "state" = "State Management"
        "rids" = "Registry System"
        "ruleset" = "Detection Ruleset"
        "suricata" = "Suricata Network IDS"
        "npcap" = "Npcap Network Driver"
        "vendor" = "Vendor Libraries"
        "samples" = "Sample Configurations"
        "supervisor" = "Service Supervisor"
        "tools" = "Management Tools"
    }
    
    $foundComponents = 0
    foreach ($component in $optionalComponents.GetEnumerator()) {
        if (Test-Path $component.Key) {
            $foundComponents++
            Write-Host "    ✓ $($component.Value)" -ForegroundColor Green
        } else {
            Write-Host "    - $($component.Value) (not found)" -ForegroundColor Yellow
        }
    }
    
    Write-Info "Found $foundComponents of $($optionalComponents.Count) optional components"
    return $foundComponents
}

# Create LICENSE file if missing
function Ensure-LicenseFile {
    if (!(Test-Path "LICENSE")) {
        Write-Warning "LICENSE file not found. Creating default license..."
        
        $defaultLicense = @"
RiskNoX Monitoring Agent - End User License Agreement

Copyright (c) 2024 RiskNoX Security

This software is provided for security monitoring purposes.
By installing and using this software, you agree to comply with all applicable laws and regulations.

For full license terms, please visit: https://risknox.com/license
"@
        
        Set-Content -Path "LICENSE" -Value $defaultLicense -Force
        Write-Success "Default LICENSE file created"
    } else {
        Write-Success "LICENSE file found"
    }
}

# Get file size in MB
function Get-FileSizeMB {
    param([string]$FilePath)
    
    if (Test-Path $FilePath) {
        $size = (Get-Item $FilePath).Length
        return [math]::Round($size / 1MB, 2)
    }
    return 0
}

# Main build function
function Build-Installer {
    param(
        [string]$NsisPath,
        [string]$OutputDirectory
    )
    
    Write-Header "Building Installer"
    
    # Ensure output directory exists
    if (!(Test-Path $OutputDirectory)) {
        New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
        Write-Info "Created output directory: $OutputDirectory"
    }
    
    # Build information
    Write-Info "Build Configuration:"
    Write-Host "    NSI Script: RiskNoX-Installer.nsi" -ForegroundColor Gray
    Write-Host "    Output: $OutputDirectory\RiskNoX-Monitoring-Agent-Installer.exe" -ForegroundColor Gray
    Write-Host "    NSIS: $NsisPath" -ForegroundColor Gray
    Write-Host ""
    
    # Execute NSIS
    Write-Info "Executing NSIS compiler..."
    try {
        $process = Start-Process -FilePath $NsisPath -ArgumentList @("/NOCD", "RiskNoX-Installer.nsi") -Wait -PassThru -NoNewWindow
        
        if ($process.ExitCode -ne 0) {
            throw "NSIS compiler failed with exit code: $($process.ExitCode)"
        }
        
        Write-Success "NSIS compilation completed successfully"
    }
    catch {
        Write-Error "NSIS compilation failed: $($_.Exception.Message)"
        return $false
    }
    
    # Check if installer was created
    $installerPath = "RiskNoX-Monitoring-Agent-Installer.exe"
    if (!(Test-Path $installerPath)) {
        Write-Error "Installer file was not created!"
        return $false
    }
    
    # Move to output directory
    $finalPath = Join-Path $OutputDirectory "RiskNoX-Monitoring-Agent-Installer.exe"
    Move-Item -Path $installerPath -Destination $finalPath -Force
    
    Write-Success "Installer created successfully"
    return $finalPath
}

# Display build results
function Show-BuildResults {
    param([string]$InstallerPath)
    
    Write-Header "Build Results"
    
    $fileSize = Get-FileSizeMB -FilePath $InstallerPath
    
    Write-Host ""
    Write-Host "🎉 BUILD SUCCESSFUL!" -ForegroundColor Green
    Write-Host ""
    Write-Host "Installer Details:" -ForegroundColor Cyan
    Write-Host "  Location: $InstallerPath" -ForegroundColor White
    Write-Host "  Size: $fileSize MB" -ForegroundColor White
    Write-Host ""
    
    Write-Host "Included Components:" -ForegroundColor Cyan
    Write-Host "  ✓ Core monitoring agent components" -ForegroundColor Green
    Write-Host "  ✓ Service supervisor system" -ForegroundColor Green
    Write-Host "  ✓ Management tools and utilities" -ForegroundColor Green
    Write-Host "  ✓ Active response system" -ForegroundColor Green
    Write-Host "  ✓ Suricata network IDS" -ForegroundColor Green
    Write-Host "  ✓ Configuration management" -ForegroundColor Green
    Write-Host "  ✓ Automatic service installation" -ForegroundColor Green
    Write-Host ""
    
    Write-Host "Installation Requirements:" -ForegroundColor Cyan
    Write-Host "  • Windows 10 or later (64-bit)" -ForegroundColor White
    Write-Host "  • Administrator privileges" -ForegroundColor White
    Write-Host "  • 500+ MB free disk space" -ForegroundColor White
    Write-Host ""
    
    Write-Host "Installation Path:" -ForegroundColor Cyan
    Write-Host "  C:\Program Files\RiskNoX\MonitoringAgent" -ForegroundColor White
    Write-Host ""
    
    Write-Host "Post-Installation:" -ForegroundColor Cyan
    Write-Host "  • Windows service configured automatically" -ForegroundColor White
    Write-Host "  • Start Menu shortcuts created" -ForegroundColor White
    Write-Host "  • Service runs 'RiskNoXServiceControl.ps1 install'" -ForegroundColor White
    Write-Host ""
    
    # Ask to open directory
    $response = Read-Host "Open output directory? (y/n)"
    if ($response -eq 'y' -or $response -eq 'Y') {
        Invoke-Item (Split-Path $InstallerPath -Parent)
    }
}

# Main execution
try {
    Show-Banner
    
    # Find NSIS
    $nsisPath = Find-NSIS
    if (!$nsisPath) {
        Write-Error "NSIS (Nullsoft Scriptable Install System) not found!"
        Write-Host ""
        Write-Info "Please install NSIS from: https://nsis.sourceforge.io/Download"
        Write-Info "Install to the default location and try again."
        Write-Host ""
        exit 1
    }
    
    Write-Success "Found NSIS at: $nsisPath"
    
    # Check files if not skipping
    if (!$SkipChecks) {
        Write-Header "Pre-Build Checks"
        
        # Check required files
        if (!(Test-RequiredFiles)) {
            Write-Error "Required files missing. Cannot proceed with build."
            Write-Host ""
            Write-Info "Ensure all required files are present before building."
            exit 1
        }
        
        # Check optional components
        $componentCount = Test-OptionalComponents
        Write-Info "Optional components will be included if present"
        
        # Ensure LICENSE file
        Ensure-LicenseFile
        
        Write-Success "Pre-build checks completed"
    } else {
        Write-Warning "Skipping pre-build checks (as requested)"
    }
    
    # Build installer
    $installerPath = Build-Installer -NsisPath $nsisPath -OutputDirectory $OutputDir
    
    if (!$installerPath) {
        Write-Error "Build failed!"
        exit 1
    }
    
    # Show results
    Show-BuildResults -InstallerPath $installerPath
    
    Write-Host ""
    Write-Host "Build completed successfully! 🚀" -ForegroundColor Green
    Write-Host ""
}
catch {
    Write-Host ""
    Write-Error "FATAL ERROR: $($_.Exception.Message)"
    Write-Host ""
    Write-Host "Stack Trace:" -ForegroundColor Red
    Write-Host $_.ScriptStackTrace -ForegroundColor Red
    Write-Host ""
    exit 1
}