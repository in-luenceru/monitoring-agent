#!/bin/bash
DAEMONS="monitoring-modulesd monitoring-logcollector monitoring-syscheckd monitoring-agentd monitoring-execd"
DIR="/workspaces/monitoring-agent"
echo "Testing status:"
RETVAL=0
for i in ${DAEMONS}; do
    if ls ${DIR}/var/run/${i}-*.pid > /dev/null 2>&1; then
        echo "${i} has PID files..."
        for pid in `cat ${DIR}/var/run/${i}-*.pid 2>/dev/null`; do
            if ps -p ${pid} > /dev/null 2>&1 && kill -0 ${pid} > /dev/null 2>&1; then
                echo "${i} is running (PID: ${pid})..."
            else
                echo "${i} not running (stale PID: ${pid})..."
                RETVAL=1
            fi
        done
    else
        echo "${i} not running (no PID files)..."
        RETVAL=1
    fi
done
echo "Exit code would be: $RETVAL"
