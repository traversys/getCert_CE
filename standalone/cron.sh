#!/bin/bash
# (c) Copyright 2015-2021, Traversys Limited
#

source <(grep 'root =' ../config.ini | sed 's/ *= */=/g')

if [ "$TIDEWAY" == "" ]; then
          export TIDEWAY=/usr/tideway
fi
. $TIDEWAY/tw_setup

mv traversys_getCert.cron /usr/tideway/etc/cron/
echo "# Every evening at 6pm" >> /usr/tideway/etc/cron/traversys_getCert.cron
echo "0 18 * * * $root/getcert" >> /usr/tideway/etc/cron/traversys_getCert.cron
tw_cron_update
echo ""
