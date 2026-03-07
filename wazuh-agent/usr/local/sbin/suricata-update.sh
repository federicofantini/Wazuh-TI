#!/bin/bash
set -e

LOG=/var/log/suricata/update.log
DATE=$(date '+%F %T')

echo "[$DATE] Starting suricata-update" >> $LOG

/usr/bin/suricata-update >> $LOG 2>&1

# Test configuration before reload
/sbin/suricata -T -c /etc/suricata/suricata.yaml >> $LOG 2>&1

# Reload service only if test succeeds
/bin/systemctl reload suricata >> $LOG 2>&1

echo "[$DATE] Update completed" >> $LOG