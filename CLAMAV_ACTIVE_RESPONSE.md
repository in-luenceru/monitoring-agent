# ClamAV Active Response - Integration & Usage Guide

This document provides a step-by-step guide to integrating and testing the ClamAV active response.

## 1. Manager Configuration

To enable the manager to trigger ClamAV scans, add the command definition to the manager's configuration.

**File:** `/var/ossec/etc/ossec.conf` (on the Manager)

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

---

## 3. Triggering Methods

### Method A: Direct Trigger (agent_control)

Trigger scan on a **specific agent** using `agent_control`:

```bash
/var/ossec/bin/agent_control -u <agent_id> -f clamav-scan -b 0.0.0.0
```

- `-u <agent_id>`: The ID of the agent (e.g., `003`)
- `-f clamav-scan`: The command name from manager's ossec.conf
- `-b 0.0.0.0`: Required dummy IP (ignored by scan script)

### Method B: Log Injection Trigger (Recommended for ALL Agents) ⭐

Trigger scans on **all connected agents** using log injection + custom rules.

#### Step 1: Deploy Manager Config Files

Copy the configuration files from `src/win32/clamav/manager-config/` to your manager:

| File | Deploy To |
|------|-----------|
| `clamav_trigger_decoder.xml` | `/var/ossec/etc/decoders/local_decoder.xml` |
| `clamav_trigger_rules.xml` | `/var/ossec/etc/rules/local_rules.xml` |
| `clamav_active_response_config.xml` | `/var/ossec/etc/ossec.conf` |

#### Step 2: Restart Manager

```bash
systemctl restart wazuh-manager
```

#### Step 3: Trigger Scan

```bash
# Quick scan on all agents
echo "CLAMAV_MANUAL_SCAN scan_type:quickscan" | /var/ossec/bin/wazuh-logtest

# Full scan on all agents  
echo "CLAMAV_MANUAL_SCAN scan_type:fullscan" | /var/ossec/bin/wazuh-logtest
```

---

## 4. Automatic Triggers (Active Response)

Configure automatic scans based on alerts in the Manager's `ossec.conf`:

### Trigger on Suspicious File Activity (Syscheck)

```xml
<active-response>
  <disabled>no</disabled>
  <command>clamav-scan</command>
  <location>local</location>
  <rules_group>syscheck</rules_group>
  <level>7</level>
</active-response>
```

### Trigger on Specific Rule IDs

```xml
<active-response>
  <disabled>no</disabled>
  <command>clamav-scan</command>
  <location>local</location>
  <rules_id>52502,52523,52531</rules_id>
</active-response>
```

---

## 5. Verification & Logs

### On the Manager

```bash
tail -f /var/ossec/logs/active-responses.log
```

### On the Agent (Windows)

| Log | Path |
|-----|------|
| Active Response | `C:\Program Files\monitoring-agent\active-response\active-responses.log` |
| ClamAV Scan | `C:\Program Files\monitoring-agent\clamav\logs\clamscan.log` |

---

## 6. Troubleshooting

| Issue | Solution |
|-------|----------|
| "Invalid argument combination" | Include `-b 0.0.0.0` with agent_control |
| Command not sent | Check agent ID is correct and active (`agent_control -l`) |
| Scan doesn't start | Check `active-responses.log` on agent for errors |
| Log injection not working | Verify decoder/rules deployed and manager restarted |

---

## Reference Files

Manager configuration files are located at:
```
src/win32/clamav/manager-config/
├── README.md
├── clamav_trigger_decoder.xml
├── clamav_trigger_rules.xml
└── clamav_active_response_config.xml
```

