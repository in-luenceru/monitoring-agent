Set-StrictMode -Off
$ErrorActionPreference = "SilentlyContinue"

$token = ((Invoke-WebRequest "https://localhost:55000/security/user/authenticate" -Method POST -Headers @{Authorization="Basic d2F6dWg6d2F6dWg="} -SkipCertificateCheck -UseBasicParsing) | ConvertFrom-Json).data.token
$h = @{Authorization="Bearer $token"}

$ports = ((Invoke-WebRequest "https://localhost:55000/syscollector/001/ports?limit=100" -Headers $h -SkipCertificateCheck -UseBasicParsing) | ConvertFrom-Json).data.affected_items
$scanTime = if ($ports -and $ports[0].scan.time) { $ports[0].scan.time } else { (Get-Date -Format "yyyy-MM-ddTHH:mm:ss") }
$ext    = $ports | Where-Object { $_.state -eq "established" -and $_.remote.ip -notmatch "^(127\.|0\.0\.0\.0|::)" -and $_.local.ip -notmatch "^127\." } | Sort-Object { [int]$_.remote.port } -Descending
$listen = $ports | Where-Object { $_.state -eq "listening" } | Sort-Object { [int]$_.local.port }

$pycode = 'import json
from collections import defaultdict
cnt=defaultdict(int)
ev=[]
for line in open("/var/ossec/logs/alerts/alerts.json"):
    try:
        d=json.loads(line)
        rid=d.get("rule",{}).get("id","")
        cnt[rid]+=1
        ev.append((d.get("timestamp","")[:19].replace("T"," "),rid,int(d.get("rule",{}).get("level",0)),d.get("rule",{}).get("description","")[:50],d.get("data",{}).get("dstuser","")[:14],d.get("data",{}).get("id","")))
    except:
        pass
seen={}
for ts,rid,lvl,desc,user,eid in ev:
    if rid not in seen or ts > seen[rid][0]:
        seen[rid]=(ts,rid,lvl,desc,user,eid)
for v in sorted(seen.values(),key=lambda x:-x[2]):
    print("%s|%s|%s|%s|%s|%s|%s" % (v[0],v[1],v[2],v[3],v[4],v[5],cnt[v[1]]))
'
$pycode | Set-Content "$env:TEMP\wa_alerts.py" -Encoding UTF8
$alerts = Get-Content "$env:TEMP\wa_alerts.py" | docker exec -i monitoring-agent-manager python3 2>&1

$L  = "=" * 100
$L2 = "-" * 100

Write-Host ""
Write-Host $L
Write-Host "  WAZUH MANAGER -- NETWORK EVENTS REPORT"
Write-Host "  Agent: DESKTOP-IVBQT1T  |  Host IP: 192.168.1.3  |  Manager: v4.13.1 (Docker)"
Write-Host "  Syscollector scan: $scanTime"
Write-Host $L

Write-Host ""
Write-Host "  [1] ESTABLISHED OUTBOUND CONNECTIONS  ($($ext.Count) active)"
Write-Host $L2
Write-Host ("  " + ("{0,-22} {1,-15} {2,-7}  {3,-22} {4,-7} {5,-5} {6}" -f "PROCESS","SRC_IP","S_PORT","DST_IP","D_PORT","PROTO","NOTE"))
Write-Host $L2
foreach ($p in $ext) {
    $note = if ($p.remote.port -eq 80) {"[HTTP!]"} elseif ($p.remote.port -eq 443) {"[HTTPS]"} else {""}
    Write-Host ("  " + ("{0,-22} {1,-15} {2,-7}  {3,-22} {4,-7} {5,-5} {6}" -f $p.process,$p.local.ip,$p.local.port,$p.remote.ip,$p.remote.port,$p.protocol,$note))
}
Write-Host $L2

Write-Host ""
Write-Host "  [2] OUTBOUND CONNECTIONS -- GROUPED BY PROCESS"
Write-Host $L2
Write-Host ("  " + ("{0,-22} {1,-6} {2}" -f "PROCESS","CONNS","REMOTE ENDPOINTS"))
Write-Host $L2
$ext | Group-Object process | Sort-Object Count -Descending | ForEach-Object {
    $eps = ($_.Group | ForEach-Object { "$($_.remote.ip):$($_.remote.port)" }) -join "   "
    Write-Host ("  " + ("{0,-22} {1,-6} {2}" -f $_.Name, $_.Count, $eps))
}
Write-Host $L2

Write-Host ""
Write-Host "  [3] LISTENING SERVICES  ($($listen.Count) ports)"
Write-Host $L2
Write-Host ("  " + ("{0,-22} {1,-22} {2,-8} {3}" -f "PROCESS","BIND_IP","PORT","PROTO"))
Write-Host $L2
foreach ($p in $listen) {
    Write-Host ("  " + ("{0,-22} {1,-22} {2,-8} {3}" -f $p.process,$p.local.ip,$p.local.port,$p.protocol))
}
Write-Host $L2

$tot = ($alerts | ForEach-Object { $parts = $_ -split "\|"; if ($parts.Count -ge 7) { [int]$parts[6] } } | Measure-Object -Sum).Sum

Write-Host ""
Write-Host "  [4] WAZUH SECURITY ALERTS  ($($alerts.Count) unique rules,  $tot total events)"
Write-Host $L2
Write-Host ("  " + ("{0,-20} {1,-7} {2,-4} {3,-50} {4,-14} {5,-12} {6}" -f "TIMESTAMP","RULE","LVL","DESCRIPTION","USER","EVENT_ID","HITS"))
Write-Host $L2
foreach ($line in $alerts) {
    $p = $line -split "\|"
    if ($p.Count -ge 7) {
        Write-Host ("  " + ("{0,-20} {1,-7} {2,-4} {3,-50} {4,-14} EventID:{5,-8} x{6}" -f $p[0],$p[1],$p[2],$p[3],$p[4],$p[5],$p[6]))
    }
}
Write-Host $L
Write-Host "  NOTE: HTTP(80) = unencrypted. Sysmon64 has 4x HTTP to 104.18.38.233 (Cloudflare CDN)."
Write-Host $L
Write-Host ""
