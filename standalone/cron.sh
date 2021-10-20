#!/bin/bash
# (c) Copyright 2015-2021, Traversys Limited
#

source <(grep 'root =' ../config.ini | sed 's/ *= */=/g')

if [ "$TIDEWAY" == "" ]; then
          export TIDEWAY=/usr/tideway
fi
. $TIDEWAY/tw_setup

cp traversys_getCert.cron /usr/tideway/etc/cron/
tw_cron_update
