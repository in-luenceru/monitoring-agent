$ErrorActionPreference = "Stop"

$TaskName = "SuricataLogClear"

# Check if task exists and remove it
$existingTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($existingTask) {
    Write-Host "Found task '$TaskName'. Unregistering..."
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    Write-Host "Successfully removed scheduled task '$TaskName'."
} else {
    Write-Host "Task '$TaskName' does not exist."
}
