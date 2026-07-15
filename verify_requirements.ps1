$r   = (docker exec monitoring-agent-manager cat /var/ossec/etc/rules/local_rules.xml 2>&1) -join "`n"
$d   = (docker exec monitoring-agent-manager cat /var/ossec/etc/decoders/local_decoder.xml 2>&1) -join "`n"
$m   = (docker exec monitoring-agent-manager cat /var/ossec/etc/shared/default/merged.mg 2>&1) -join "`n"
$a   = (docker exec monitoring-agent-manager /var/ossec/bin/agent_control -l 2>&1) -join "`n"
$p   = (netstat -an) -join "`n"
$svc = (Get-Service "MonitoringSvc" -EA SilentlyContinue).Status
$alog = (Get-Content "C:\Program Files (x86)\monitoring-agent\ossec.log" -Tail 30 -EA SilentlyContinue) -join "`n"
$agCfg = Get-Content "C:\Program Files (x86)\monitoring-agent\ossec.conf" -Raw -EA SilentlyContinue
$qs  = docker exec monitoring-agent-manager bash -c 'printf "CLAMAV_MANUAL_SCAN scan_type:quickscan\n" | /var/ossec/bin/wazuh-logtest 2>&1'
$fs  = docker exec monitoring-agent-manager bash -c 'printf "CLAMAV_MANUAL_SCAN scan_type:fullscan\n" | /var/ossec/bin/wazuh-logtest 2>&1'

$pass = 0; $fail = 0
function chk($label, $result) {
    if ($result) { $script:pass++; Write-Host "  [PASS] $label" -ForegroundColor Green }
    else          { $script:fail++; Write-Host "  [FAIL] $label" -ForegroundColor Red }
}

Write-Host ""
Write-Host "================================================"
Write-Host "  REQUIREMENT VERIFICATION REPORT"
Write-Host "================================================"

Write-Host "`n[A] ClamAV Active Response Rules"
chk "100499 level=3 decoded_as=clamav_trigger"  ($r -match '100499' -and $r -match 'clamav_trigger')
chk "100500 level=10 AR trigger (if_sid=100499)" ($r -match '100500.*level="10"')
chk "100501 quickscan field match"               ($r -match '100501' -and $r -match 'quickscan')
chk "100502 fullscan field match"                ($r -match '100502' -and $r -match 'fullscan')
chk "clamav_trigger decoder loaded"              ($d -match 'clamav_trigger')
chk "clamav_trigger_params decoder loaded"       ($d -match 'clamav_trigger_params')
chk "logtest: quickscan -> rule 100501"          ([bool](($qs | Where-Object {$_ -match "100501"}).Count -gt 0))
chk "logtest: fullscan  -> rule 100502"          ([bool](($fs | Where-Object {$_ -match "100502"}).Count -gt 0))

Write-Host "`n[B] Windows System State Rules (EventLog)"
chk "100200 if_sid=83202 id=6005 boot"           ($r -match '100200' -and $r -match '<id>6005</id>')
chk "100201 if_sid=18101 id=6006 clean shutdown" ($r -match '100201' -and $r -match '<id>6006</id>')
chk "100202 if_sid=18101 id=6008 level=12 crash" ($r -match '100202' -and $r -match '<id>6008</id>')
chk "100203 if_sid=18101 id=1074 planned restart"($r -match '100203' -and $r -match '<id>1074</id>')
chk "100204 if_sid=18104 id=4608 audit start"    ($r -match '100204' -and $r -match '<id>4608</id>')

Write-Host "`n[C] Windows Privilege Use Rules"
chk "100210 if_sid=18104 id=4672 priv logon"     ($r -match '100210' -and $r -match '<id>4672</id>')
chk "100211 if_sid=18104 id=4688 new process"    ($r -match '100211' -and $r -match '<id>4688</id>')
chk "100212 if_sid=18108 id=4673 priv fail"      ($r -match '100212' -and $r -match '<id>4673</id>')

Write-Host "`n[D] agent_config blocks pushed to Windows agents (merged.mg)"
chk "Suricata eve.json  log_format=json"         ($m -match "eve\.json")
chk "ClamAV clamscan.log log_format=syslog"      ($m -match "clamscan\.log")
chk "Application log_format=eventlog"            ($m -match "Application" -and $m -match "eventlog")
chk "Security    log_format=eventlog"            ($m -match "Security"    -and $m -match "eventlog")
chk "System      log_format=eventlog"            ($m -match "System"      -and $m -match "eventlog")
chk "Agent applied merged.mg"                    ($alog -match "shared configuration changes")
chk "clamav-scan.exe in AR section of merged.mg" ($m -match "clamav-scan")

Write-Host "`n[E] End-to-End Connectivity"
chk "Manager container running"                  ((docker inspect monitoring-agent-manager --format "{{.State.Status}}" 2>&1) -eq "running")
chk "Windows agent 001 enrolled and Active"      ($a -match "ID: 001" -and $a -match "Active")
chk "Port 1522 agent comms listening"            ($p -match "0.0.0.0:1522")
chk "Port 1523 enrollment listening"             ($p -match "0.0.0.0:1523")
chk "MonitoringSvc running"                      ($svc -eq "Running")
chk "Agent ossec.conf has clamav-scan command"   ($agCfg -match "clamav-scan")

Write-Host ""
Write-Host "================================================"
$total = $pass + $fail
$color = if ($fail -eq 0) { "Green" } else { "Yellow" }
Write-Host "  RESULT: $pass / $total PASSED   |   $fail FAILED" -ForegroundColor $color
Write-Host "================================================"
Write-Host ""
