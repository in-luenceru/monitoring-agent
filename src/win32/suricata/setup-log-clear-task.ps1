$ErrorActionPreference = "Stop"

$TaskName = "SuricataLogClear"
$ScriptPath = "C:\Program Files (x86)\monitoring-agent\suricata\clear-suricata-logs.ps1"

# Check if task already exists
$existingTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($existingTask) {
    Write-Host "Task '$TaskName' already exists. Unregistering old task..."
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
}

# Define the action (Run PowerShell script hidden, bypassing execution policy)
$Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$ScriptPath`""

# Define the trigger (Daily at Midnight)
$Trigger = New-ScheduledTaskTrigger -Daily -At "12:00 AM"

# Define the settings (Start when available handles missed schedules if system is off)
$Settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -RunOnlyIfNetworkAvailable:$false -DontStopOnIdleEnd -ExecutionTimeLimit (New-TimeSpan -Hours 1)

# Register the task to run as SYSTEM for sufficient privileges
Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Settings $Settings -User "NT AUTHORITY\SYSTEM" -RunLevel Highest

Write-Host "Successfully registered scheduled task '$TaskName'."
Write-Host "The task will run daily at midnight, and will catch up if the system was turned off."
