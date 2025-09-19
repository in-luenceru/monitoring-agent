# Monitoring Agent Connection Test Script
# Tests enrollment, start, and connection verification

param(
    [Parameter(Mandatory=$true)]
    [string]$ManagerIP,
    
    [Parameter(Mandatory=$false)]
    [string]$ManagerPort = "1514",
    
    [Parameter(Mandatory=$false)]
    [string]$AgentName = $env:COMPUTERNAME
)

Write-Host "=======================================" -ForegroundColor Yellow
Write-Host "Monitoring Agent Connection Test" -ForegroundColor Yellow  
Write-Host "=======================================" -ForegroundColor Yellow
Write-Host ""

$agentPath = "c:\Users\ANANDHU\OneDrive\Desktop\monitoring-agent"
Set-Location $agentPath

Write-Host "Testing connection to manager: $ManagerIP`:$ManagerPort" -ForegroundColor Cyan
Write-Host ""

# Step 1: Test network connectivity to manager
Write-Host "Step 1: Testing network connectivity..." -ForegroundColor Yellow
try {
    $connection = Test-NetConnection -ComputerName $ManagerIP -Port $ManagerPort -InformationLevel Quiet -WarningAction SilentlyContinue
    if ($connection) {
        Write-Host "✓ Network connectivity to $ManagerIP`:$ManagerPort successful" -ForegroundColor Green
    } else {
        Write-Host "✗ Cannot connect to $ManagerIP`:$ManagerPort" -ForegroundColor Red
        Write-Host "Please ensure:" -ForegroundColor Yellow
        Write-Host "  - Manager is running on $ManagerIP`:$ManagerPort" -ForegroundColor White
        Write-Host "  - Firewall allows connection to port $ManagerPort" -ForegroundColor White
        Write-Host "  - Network connectivity exists" -ForegroundColor White
        return
    }
} catch {
    Write-Host "⚠ Could not test network connectivity (continuing anyway)" -ForegroundColor Yellow
}

# Step 2: Check current agent status
Write-Host ""
Write-Host "Step 2: Checking current agent status..." -ForegroundColor Yellow
& ".\monitoring-agent-control.ps1" status

# Step 3: Stop agent if running
Write-Host ""
Write-Host "Step 3: Stopping agent (if running)..." -ForegroundColor Yellow
& ".\monitoring-agent-control.ps1" stop

# Step 4: Demonstrate enrollment process
Write-Host ""
Write-Host "Step 4: Agent Enrollment Process" -ForegroundColor Yellow
Write-Host "=======================================" -ForegroundColor Yellow
Write-Host ""
Write-Host "To enroll this agent with your manager, you need to:" -ForegroundColor Cyan
Write-Host "1. Get the client key from your manager" -ForegroundColor White
Write-Host "2. Run the enrollment command" -ForegroundColor White
Write-Host ""
Write-Host "On your manager server, run:" -ForegroundColor Yellow
Write-Host "  sudo /var/ossec/bin/manage_agents" -ForegroundColor Gray
Write-Host "  # Add a new agent with name: $AgentName" -ForegroundColor Gray
Write-Host "  # Extract the key for the agent" -ForegroundColor Gray
Write-Host ""
Write-Host "Then run enrollment command:" -ForegroundColor Yellow
Write-Host "  .\monitoring-agent-control.ps1 enroll $ManagerIP $ManagerPort $AgentName" -ForegroundColor Gray
Write-Host ""

$doEnrollment = Read-Host "Do you want to proceed with enrollment now? (y/N)"
if ($doEnrollment -match '^[Yy]$') {
    Write-Host ""
    Write-Host "Starting enrollment process..." -ForegroundColor Cyan
    & ".\monitoring-agent-control.ps1" enroll $ManagerIP $ManagerPort $AgentName
    
    # Step 5: Verify enrollment
    Write-Host ""
    Write-Host "Step 5: Verifying enrollment..." -ForegroundColor Yellow
    & ".\monitoring-agent-control.ps1" status
    
    # Step 6: Start agent
    Write-Host ""
    Write-Host "Step 6: Starting agent..." -ForegroundColor Yellow
    & ".\monitoring-agent-control.ps1" start
    
    # Step 7: Final status check
    Write-Host ""
    Write-Host "Step 7: Final status verification..." -ForegroundColor Yellow
    Start-Sleep 5  # Give agent time to connect
    & ".\monitoring-agent-control.ps1" status
    
    # Step 8: Check agent process
    Write-Host ""
    Write-Host "Step 8: Checking agent process..." -ForegroundColor Yellow
    $processes = Get-Process -Name "MONITORING_AGENT" -ErrorAction SilentlyContinue
    if ($processes) {
        Write-Host "✓ Agent process is running (PID: $($processes[0].Id))" -ForegroundColor Green
        
        # Check if agent is actually connecting
        Write-Host ""
        Write-Host "Checking recent agent logs for connection status..." -ForegroundColor Cyan
        $logFile = "windows\logs\monitoring-agent.log"
        if (Test-Path $logFile) {
            Write-Host "Recent log entries:" -ForegroundColor Yellow
            Get-Content $logFile -Tail 10 | ForEach-Object {
                if ($_ -match "Connected|ERROR|CRITICAL") {
                    if ($_ -match "Connected") {
                        Write-Host $_ -ForegroundColor Green
                    } elseif ($_ -match "ERROR|CRITICAL") {
                        Write-Host $_ -ForegroundColor Red
                    } else {
                        Write-Host $_ -ForegroundColor White
                    }
                }
            }
        }
    } else {
        Write-Host "✗ Agent process is not running" -ForegroundColor Red
    }
    
    Write-Host ""
    Write-Host "=======================================" -ForegroundColor Yellow
    Write-Host "Manager Verification Instructions" -ForegroundColor Yellow
    Write-Host "=======================================" -ForegroundColor Yellow
    Write-Host "On your manager server ($ManagerIP), verify the agent connection:" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "1. Check agent status:" -ForegroundColor White
    Write-Host "   sudo /var/ossec/bin/agent_control -l" -ForegroundColor Gray
    Write-Host ""
    Write-Host "2. Check for agent in active agents list:" -ForegroundColor White
    Write-Host "   sudo /var/ossec/bin/agent_control -lc" -ForegroundColor Gray
    Write-Host ""
    Write-Host "3. View manager logs:" -ForegroundColor White
    Write-Host "   sudo tail -f /var/ossec/logs/ossec.log" -ForegroundColor Gray
    Write-Host ""
    Write-Host "4. Look for entries like:" -ForegroundColor White
    Write-Host "   'Agent ID 001 ($AgentName) connected'" -ForegroundColor Gray
    Write-Host ""
    
} else {
    Write-Host ""
    Write-Host "Manual enrollment instructions:" -ForegroundColor Yellow
    Write-Host "1. Enroll: .\monitoring-agent-control.ps1 enroll $ManagerIP $ManagerPort $AgentName" -ForegroundColor White
    Write-Host "2. Start:  .\monitoring-agent-control.ps1 start" -ForegroundColor White
    Write-Host "3. Status: .\monitoring-agent-control.ps1 status" -ForegroundColor White
}

Write-Host ""