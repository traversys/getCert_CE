#!/bin/bash
# (c) Copyright 2015-2021, Traversys Limited
#

source <(grep "root =" config.ini | sed 's/ *= */=/g')
source <(grep "cron =" config.ini | sed 's/ *= */=/g')

if [ "$TIDEWAY" == "" ]; then
          export TIDEWAY=/usr/tideway
fi
. $TIDEWAY/tw_setup

echo "$cron $root/get" >> traversys_getCert.cron
mv traversys_getCert.cron /usr/tideway/etc/cron/
tw_cron_update
echo ""
