ClamAV Active Response Implementation Guide
This guide details the complete configuration required to trigger ClamAV scans on Windows agents from the Wazuh Manager using log injection.

1. Prerequisites
Wazuh Manager: Running on Linux/Docker.
Wazuh Agent: Installed on Windows.
ClamAV: Installed on Windows Agent.
ClamAV Scripts: 
ClamAVControl.ps1
 available on the agent.
2. Manager Configuration (Linux/Docker)
These configurations enable the manager to parse the trigger logs and send the command to agents.

A. Add Local Decoder
File: /var/ossec/etc/decoders/local_decoder.xml

xml
<decoder name="clamav_trigger">
  <prematch>^CLAMAV_MANUAL_SCAN</prematch>
</decoder>
<decoder name="clamav_trigger_params">
  <parent>clamav_trigger</parent>
  <regex offset="after_parent">scan_type:(\w+)</regex>
  <order>scan_type</order>
</decoder>
B. Add Local Rules
File: /var/ossec/etc/rules/local_rules.xml

xml
<group name="clamav,">
  <!-- Base rule: Detect the trigger log -->
  <rule id="100499" level="3">
    <decoded_as>clamav_trigger</decoded_as>
    <description>ClamAV manual scan trigger received</description>
    <group>clamav,trigger</group>
  </rule>
  <!-- Active Response trigger rule -->
  <rule id="100500" level="10">
    <if_sid>100499</if_sid>
    <description>Manual ClamAV scan triggered from manager</description>
    <group>clamav,manual_scan</group>
  </rule>
</group>
C. Configure Active Response
File: /var/ossec/etc/ossec.conf

Add the command definition and active response block.

IMPORTANT

The <location> must be set to all (or specific_agent) to ensure the command runs on the agent, not the manager.

xml
<!-- Command Definition -->
<command>
  <name>clamav-scan</name>
  <executable>clamav-scan.exe</executable>
  <timeout_allowed>no</timeout_allowed>
</command>
<!-- Active Response Configuration -->
<active-response>
  <disabled>no</disabled>
  <command>clamav-scan</command>
  <location>all</location>
  <rules_id>100500</rules_id>
  <timeout>0</timeout>
</active-response>
Restart the Manager:

bash
# Docker
docker restart <container_id>
# Systemd
systemctl restart wazuh-manager
3. Agent Configuration (Windows)
Ensure the agent has the executable and the PowerShell script in the correct directory structure.

A. Executable Location
The clamav-scan.exe (Wazuh active response executable) must be in: 
C:\Program Files (x86)\monitoring-agent\active-response\bin\clamav-scan.exe

B. Script Location
The executable expects the control script at a relative path ..\clamav\ClamAVControl.ps1.

Required Path: 
C:\Program Files (x86)\monitoring-agent\active-response\clamav\ClamAVControl.ps1

NOTE

If you have the script in another location (e.g., the main clamav folder), copy it to this specific active-response directory.

Powershell verify/create command:

powershell
New-Item -ItemType Directory -Force -Path "C:\Program Files (x86)\monitoring-agent\active-response\clamav"
Copy-Item "C:\Path\To\Your\ClamAVControl.ps1" "C:\Program Files (x86)\monitoring-agent\active-response\clamav\ClamAVControl.ps1"
4. How to Trigger the Scan
You can trigger the scan on all agents by injecting a specific log message into the manager's active-responses.log.

Command (Run on Manager)
Use docker exec (if using Docker) or run directly on the shell.

Syntax:

bash
echo "<TIMESTAMP> localhost CLAMAV_MANUAL_SCAN scan_type:<TYPE>" >> /var/ossec/logs/active-responses.log
Example (Quick Scan):

bash
# Docker
docker exec -i <container_id> sh -c 'echo "$(date "+%b %d %H:%M:%S") localhost CLAMAV_MANUAL_SCAN scan_type:quickscan" >> /var/ossec/logs/active-responses.log'
# Native Linux
echo "$(date "+%b %d %H:%M:%S") localhost CLAMAV_MANUAL_SCAN scan_type:quickscan" >> /var/ossec/logs/active-responses.log
Full System Scan
To trigger a full scan of all fixed drives on the agent:

bash
# Docker
docker exec -i <container_id> sh -c 'echo "$(date "+%b %d %H:%M:%S") localhost CLAMAV_MANUAL_SCAN scan_type:fullscan" >> /var/ossec/logs/active-responses.log'
CAUTION

Performance Impact: A full system scan checks all files on all fixed drives. This process can be CPU and I/O intensive and may take a significant amount of time to complete. Use this command judiciously, preferably during maintenance windows.

Verification
Check Manager Alerts: tail -f /var/ossec/logs/alerts/alerts.log

Look for Rule 100500 "Manual ClamAV scan triggered from manager".

Check Agent Logs: Get-Content "C:\Program Files (x86)\monitoring-agent\active-response\active-responses.log" -Wait Look for "ClamAV scan completed".