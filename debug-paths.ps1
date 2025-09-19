# Debug script to check config file paths
$script:AGENT_HOME = "c:\Users\ANANDHU\OneDrive\Desktop\monitoring-agent"

# Helper function to find config files with case-insensitive matching
function Find-ConfigFile {
    param([string]$FullPath)
    
    Write-Host "Looking for: $FullPath"
    
    if (Test-Path $FullPath) {
        Write-Host "Found exact match: $FullPath"
        return $FullPath
    }
    
    $parentDir = Split-Path $FullPath -Parent
    $expectedFile = Split-Path $FullPath -Leaf
    
    Write-Host "Parent dir: $parentDir"
    Write-Host "Expected file: $expectedFile"
    
    # Try to find file with different case
    try {
        $files = Get-ChildItem -Path $parentDir -ErrorAction SilentlyContinue
        Write-Host "Files in directory:"
        $files | ForEach-Object { Write-Host "  $($_.Name)" }
        
        foreach ($file in $files) {
            if ($file.Name -ieq $expectedFile) {
                Write-Host "Found case-insensitive match: $($file.FullName)"
                return $file.FullName
            }
        }
    } catch {
        Write-Host "Error searching directory: $_"
    }
    
    Write-Host "No match found, returning original: $FullPath"
    return $FullPath  # Return original path as fallback
}

# Test the function
$windowsEtcDir = Join-Path $script:AGENT_HOME "windows\etc"
Write-Host "Windows etc dir: $windowsEtcDir"

$CONFIG_FILE = Find-ConfigFile (Join-Path $windowsEtcDir "OSSEC.CONF")
$CLIENT_KEYS = Find-ConfigFile (Join-Path $windowsEtcDir "client.keys")

Write-Host ""
Write-Host "Results:"
Write-Host "CONFIG_FILE: $CONFIG_FILE"
Write-Host "CLIENT_KEYS: $CLIENT_KEYS"
Write-Host "Config exists: $(Test-Path $CONFIG_FILE)"
Write-Host "Keys exist: $(Test-Path $CLIENT_KEYS)"