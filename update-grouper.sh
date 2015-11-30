#!/bin/sh -e

# Script à exécuter dans un CRON une fois par jour.

GROUPER_HOME=/usr/local/grouper/grouper
export GROUPER_HOME

curDir=$(dirname $0)

out_file=$curDir/temp.gsh
conf_file=$curDir/config.ini

# Log files
GROUPER_LOG=/var/log/grouper

GEN_GSH_LOG=$GROUPER_LOG/GSHcreator.log.
EXEC_GSH_LOG=$GROUPER_LOG/GSHcreator-gsh.log
PSP_EXPORT_LOG=$GROUPER_LOG/GSHcreator-psp-bulkSync.log

cd $curDir
echo -e "Creating GSH temporary file..."
$curDir/GSHcreator.py $conf_file $out_file $GEN_GSH_LOG && echo -e "Done\n"

echo -e "Execute GSH temporary file..."
$GROUPER_HOME/bin/gsh $out_file >> $EXEC_GSH_LOG && echo -e "Done\n"

# ensure modifications go to LDAP (for modifications not handled by export-modified-groups-to-LDAP)
echo -e "Ensure modifications go to LDAP..."
$GROUPER_HOME/bin/gsh -psp -bulkSync >> $PSP_EXPORT_LOG && echo -e "Done\n"

exit 0
