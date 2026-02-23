$ErrorActionPreference = "Stop"

$LogDir = "C:\Program Files (x86)\monitoring-agent\suricata\log"
$LogsToClear = @("eve.json", "fast.log", "stats.log")

foreach ($LogFile in $LogsToClear) {
    $LogPath = Join-Path -Path $LogDir -ChildPath $LogFile
    if (Test-Path -Path $LogPath -PathType Leaf) {
        try {
            # Clear-Content empties the file without breaking file handles
            Clear-Content -Path $LogPath -Force
            Write-Host "Successfully cleared: $LogPath"
        } catch {
            Write-Error "Failed to clear $LogPath. Error: $($_.Exception.Message)"
        }
    } else {
        Write-Host "Log file not found, skipping: $LogPath"
    }
}
