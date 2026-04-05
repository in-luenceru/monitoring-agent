#!/bin/sh

## Stop and remove application
sudo /Library/MonitoringAgent/bin/monitoring-control stop
sudo /bin/rm -r /Library/MonitoringAgent*

# remove launchdaemons
/bin/rm -f /Library/LaunchDaemons/com.monitoring.agent.plist

## remove StartupItems
/bin/rm -rf /Library/StartupItems/MONITORING

## Remove User and Groups
/usr/bin/dscl . -delete "/Users/monitoring"
/usr/bin/dscl . -delete "/Groups/monitoring"

/usr/sbin/pkgutil --forget com.monitoring.pkg.monitoring-agent
/usr/sbin/pkgutil --forget com.monitoring.pkg.monitoring-agent-etc

# Also clean up any legacy wazuh artifacts if present
/bin/rm -f /Library/LaunchDaemons/com.wazuh.agent.plist 2>/dev/null
/bin/rm -rf /Library/StartupItems/WAZUH 2>/dev/null
/usr/bin/dscl . -delete "/Users/wazuh" 2>/dev/null
/usr/bin/dscl . -delete "/Groups/wazuh" 2>/dev/null
/usr/sbin/pkgutil --forget com.wazuh.pkg.wazuh-agent 2>/dev/null
/usr/sbin/pkgutil --forget com.wazuh.pkg.wazuh-agent-etc 2>/dev/null

# In case it was installed via Puppet pkgdmg provider
if [ -e /var/db/.puppet_pkgdmg_installed_monitoring-agent ]; then
    rm -f /var/db/.puppet_pkgdmg_installed_monitoring-agent
fi

echo
echo "Monitoring Agent correctly removed from the system."
echo

exit 0
