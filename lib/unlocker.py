#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2017-2021 Wes Moskal-Fitzpatrick
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Author: Wes Moskal-Fitzpatrick (Traversys)
#
# Created: 2020-04-14
#
# Change History:
# 2020-04-14 : WMF : Unlocker file for multi-tasking.
# 2021-02-13 : WMF : Updated integrity check.
# 2021-09-22 : WMF : Updated configparser import for Python3 compatibility.
#

import os
import sys
import configparser

config = configparser.ConfigParser()

#os.chdir(os.path.dirname(sys.argv[0]))

cf = os.path.join(os.path.dirname(sys.argv[0]), "config.ini")

# Read config file
cfexists = os.path.isfile(cf)
if not cfexists:
    print("Config file missing! Cannot continue.")
    sys.exit(1)

config.read(cf)

temp = config.get('ENV', 'temp')
log = config.get('ENV', 'log')
capture = config.get('ENV', 'capture')
iplist = config.get('ENV', 'iplist')
mode = int(config.get('MODE', 'mode'))
testsubnet = config.get('TEST_SUBNET', 'testsubnet')
file = config.get('LIST_OF_IPS', 'file')
query = config.get('DISCO_QUERY', 'query')
discouser = config.get('LOGIN', 'discouser')
discopass = config.get('LOGIN', 'discopass')
timeout = config.get('TIMEOUT', 'timeout')
ports = config.get('PORTS', 'ports')

# Integrity License Check
# The md5sum is set by hide.py script on install
# integrity = os.popen('/usr/tideway/bin/tw_query -u %s -p %s --no-headings "search PatternModule where name = \'Traversys_SSL_getCert\' and active show source_md5sum" 2> /dev/null' % (discouser, discopass)).read().strip('\n').strip()

#if not integrity:
#    print("Integrity Check failed! Please reinstall getCert.")
#    sys.exit(1)

# Options
if len(sys.argv) < 2:
    print("No arguments specified.")
    sys.exit(1)
elif sys.argv[1] == "--xml":
    os.system('echo "_traversys" | gpg -d --batch --yes --quiet --no-mdc-warning --passphrase-fd 0 --decrypt %s' % (temp + "/ssl-out.gpg"))
elif sys.argv[1] == "--ssl":
    if len(sys.argv) < 3:
        print("No target specified.")
    else:
        os.system('timeout 1 openssl s_client -connect %s | openssl x509 -noout -serial' % (sys.argv[2]))
else:
    print("Arguments not recognised.")

sys.exit(0)
