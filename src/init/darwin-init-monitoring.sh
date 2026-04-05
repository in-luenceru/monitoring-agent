#!/bin/sh

# Darwin init script for Monitoring Agent.
# Copyright (C) 2025, Monitoring Solutions Inc.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

INSTALLATION_PATH=${1}
SERVICE=/Library/LaunchDaemons/com.monitoring.agent.plist
STARTUP=/Library/StartupItems/MONITORING/StartupParameters.plist
LAUNCHER_SCRIPT=/Library/StartupItems/MONITORING/Monitoring-launcher
STARTUP_SCRIPT=/Library/StartupItems/MONITORING/MONITORING

launchctl unload /Library/LaunchDaemons/com.monitoring.agent.plist 2> /dev/null

# Also unload legacy wazuh plist if it exists
launchctl unload /Library/LaunchDaemons/com.wazuh.agent.plist 2> /dev/null

mkdir -p /Library/StartupItems/MONITORING
chown root:wheel /Library/StartupItems/MONITORING
rm -f $STARTUP $STARTUP_SCRIPT $SERVICE
echo > $LAUNCHER_SCRIPT
chown root:wheel $LAUNCHER_SCRIPT
chmod u=rxw-,g=rx-,o=r-- $LAUNCHER_SCRIPT

echo '<?xml version="1.0" encoding="UTF-8"?>
 <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
 <plist version="1.0">
     <dict>
         <key>Label</key>
         <string>com.monitoring.agent</string>
         <key>ProgramArguments</key>
         <array>
             <string>'$LAUNCHER_SCRIPT'</string>
         </array>
         <key>RunAtLoad</key>
         <true/>
     </dict>
 </plist>' > $SERVICE

chown root:wheel $SERVICE
chmod u=rw-,go=r-- $SERVICE

echo '
#!/bin/sh
. /etc/rc.common

StartService ()
{
        '${INSTALLATION_PATH}'/bin/monitoring-control start
}
StopService ()
{
        '${INSTALLATION_PATH}'/bin/monitoring-control stop
}
RestartService ()
{
        '${INSTALLATION_PATH}'/bin/monitoring-control restart
}
RunService "$1"
' > $STARTUP_SCRIPT

chown root:wheel $STARTUP_SCRIPT
chmod u=rwx,go=r-x $STARTUP_SCRIPT

echo '
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" "http://
www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
       <key>Description</key>
       <string>Monitoring Security Agent</string>
       <key>Messages</key>
       <dict>
               <key>start</key>
               <string>Starting Monitoring Agent</string>
               <key>stop</key>
               <string>Stopping Monitoring Agent</string>
       </dict>
       <key>Provides</key>
       <array>
               <string>MONITORING</string>
       </array>
       <key>Requires</key>
       <array>
               <string>IPFilter</string>
       </array>
</dict>
</plist>
' > $STARTUP

chown root:wheel $STARTUP
chmod u=rw-,go=r-- $STARTUP

echo '#!/bin/sh

capture_sigterm() {
    '${INSTALLATION_PATH}'/bin/monitoring-control stop
    exit $?
}

if ! '${INSTALLATION_PATH}'/bin/monitoring-control start; then
    '${INSTALLATION_PATH}'/bin/monitoring-control stop
fi

while : ; do
    trap capture_sigterm SIGTERM
    sleep 3
done
' > $LAUNCHER_SCRIPT
