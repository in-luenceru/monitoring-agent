# ClamAV Active Response - Integration & Usage Guide

This document provides a step-by-step guide to integrating and testing the ClamAV active response.

## 1. Manager Link & Configuration

To enable the manager to trigger the ClamAV scan, you must define the command in the manager's configuration.

**File:** `/var/ossec/etc/ossec.conf` (on the Manager)

Add the following block to the `<ossec_config>` section (usually near other `<command>` blocks):

```xml
<command>
  <name>clamav-scan</name>
  <executable>clamav-scan.exe</executable>
  <timeout_allowed>no</timeout_allowed>
</command>
```

> [!NOTE]
> Restart the manager after adding this configuration:
> `systemctl restart wazuh-manager`

## 2. Agent Configuration

Ensure the agent has the necessary components:
1. `clamav-scan.exe` in `C:\Program Files\monitoring-agent\active-response\bin\`
2. ClamAV properly installed in `C:\Program Files\monitoring-agent\clamav\`

The active response command corresponds to the `executable` filename on the agent.

## 3. Manual Testing (agent_control)

You can manually trigger the scan using `agent_control`.

**Important:** The `agent_control` tool requires a dummy IP address (`-b`) even for non-network responses.

### Triggering a Quick Scan (Default)

The `clamav-scan.exe` defaults to `quickscan` when no parameters are provided.

```bash
/var/ossec/bin/agent_control -u <agent_id> -f clamav-scan -b 0.0.0.0
```

*   `-u <agent_id>`: The ID of the agent (e.g., `003`).
*   `-f clamav-scan`: The name of the command defined in manager's `ossec.conf`.
*   `-b 0.0.0.0`: Dummy IP required by Wazuh to validate the command (ignored by the scan script).

**Example Output:**
```
Wazuh agent_control: Commanded agent '003' to run 'clamav-scan'.
```

## 4. Automatic Triggers (Active Response)

To configure automatic scans based on alerts, add `<active-response>` blocks to the **Manager's** `ossec.conf`.

### Example: Trigger on Suspicious File Activity (Syscheck)
Triggers a scan when file changes are detected.

```xml
<active-response>
  <disabled>no</disabled>
  <command>clamav-scan</command>
  <location>local</location>
  <rules_group>syscheck</rules_group>
  <level>7</level>
</active-response>
```

### Example: Trigger on Specific Rules
Trigger on specific virus detection rules.

```xml
<active-response>
  <disabled>no</disabled>
  <command>clamav-scan</command>
  <location>local</location>
  <rules_id>52502,52523,52531</rules_id>
</active-response>
```

## 5. Verification & Logs

### On the Manager
Check `active-responses.log` to see if the command was sent.

```bash
tail -f /var/ossec/logs/active-responses.log
```

### On the Agent (Windows)
Check the execution logs to verify the scan ran and see the results.

**Active Response Log:**
`C:\Program Files\monitoring-agent\active-response\active-responses.log`
*Confirm the command was received.*

**ClamAV Log:**
`C:\Program Files\monitoring-agent\clamav\logs\clamscan.log`
*See the detailed scan output.*

## Troubleshooting

- **"Invalid argument combination"**: Ensure you included `-b 0.0.0.0`.
- **Command not sent**: Check if the agent ID is correct and active (`agent_control -l`).
- **Scan doesn't start**: Check `active-responses.log` on the agent for permission errors or path issues.
