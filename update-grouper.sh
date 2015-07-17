#!/bin/sh -e

# Script à exécuter dans un CRON une fois par jour.

GROUPER_HOME=/usr/local/grouper/grouper
GROUPER_LOG=/var/log/grouper

curDir=$(dirname $0)

out_file=$curDir/temp.gsh
conf_file=$curDir/config.ini
log_file=$GROUPER_LOG/GSHcreator.log.

echo -e "Creating GSH temporary file...\n"
$curDir/GSHcreator.py $conf_file $out_file $log_file

echo -e "Execute GSH temporary file...\n"
$GROUPER_HOME/bin/gsh $out >> $GROUPER_LOG/GSHcreator-gsh.log

# ensure modifications go to LDAP (for modifications not handled by export-modified-groups-to-LDAP)
echo -e "Ensure modifications go to LDAP...\n"
$GROUPER_HOME/bin/gsh -psp -bulkSync >> $GROUPER_LOG/GSHcreator-psp-bulkSync.log
