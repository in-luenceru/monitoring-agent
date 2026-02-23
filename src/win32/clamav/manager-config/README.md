# ClamAV Manager Configuration Files

These configuration files should be deployed to your **Wazuh Manager** to enable log injection-based triggering of ClamAV scans on agents.

## Files

| File | Manager Location | Purpose |
|------|------------------|---------|
| `clamav_trigger_decoder.xml` | `/var/ossec/etc/decoders/local_decoder.xml` | Parses trigger log messages |
| `clamav_trigger_rules.xml` | `/var/ossec/etc/rules/local_rules.xml` | Detects trigger and fires AR |
| `clamav_active_response_config.xml` | `/var/ossec/etc/ossec.conf` | Defines command and AR config |

## Quick Deployment

```bash
# On the Wazuh Manager:

# 1. Add decoder (append to existing or create new)
cat clamav_trigger_decoder.xml >> /var/ossec/etc/decoders/local_decoder.xml

# 2. Add rules (append to existing or create new)
cat clamav_trigger_rules.xml >> /var/ossec/etc/rules/local_rules.xml

# 3. Add command and active-response to ossec.conf
# (Manual: copy <command> and <active-response> blocks into ossec.conf)

# 4. Restart manager
systemctl restart wazuh-manager
```

## Triggering Scans

After deployment, trigger scans via:

```bash
# Inject trigger log for quick scan
echo "CLAMAV_MANUAL_SCAN scan_type:quickscan" >> /var/ossec/logs/alerts/alerts.log

# Or use wazuh-logtest for testing
echo "CLAMAV_MANUAL_SCAN scan_type:quickscan" | /var/ossec/bin/wazuh-logtest
```

## Rule IDs

- **100499**: Base trigger detection (level 3)
- **100500**: Main AR trigger (level 10)
- **100501**: Quick scan specific (optional)
- **100502**: Full scan specific (optional)
