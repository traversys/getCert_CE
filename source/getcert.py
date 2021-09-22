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
# Created: 2017-02-03
#
# Change History:
# 2019-02-03 : WMF : Updated ciphers and timeout functions. Using older version of NMAP to
#                    maintain compatibility with ADDM v10.x
# 2019-12-19 : WMF : Updated config file using ConfigParser
#                    This file replaces the ssl_capture shell script.
# 2020-03-29 : WMF : Added license key capability - performs a check for license file - if
#                    If valid, removes the 100 cert limit
# 2021-02-13 : WMF : Removed licence check for Open Source edition.
# 2021-09-22 : WMF : Updated configparser import for Python3 compatibility.
#

import os
import sys
import re
import fileinput
import configparser
import datetime
import base64
import hashlib
import shutil

config = configparser.ConfigParser()

# Read config file
cfexists = os.path.isfile('config.ini')
if not cfexists:
    print("Config file missing! Cannot continue.")
    sys.exit(1)

config.read("config.ini")

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
date = datetime.datetime.now()
unlock = False

# Integrity License Check
# The md5sum is set by hide.py script on install
#integrity = os.popen('/usr/tideway/bin/tw_query -u %s -p %s --no-headings "search PatternModule where name = \'Traversys_SSL_getCert_License\' and active show source_md5sum" 2> /dev/null' % (discouser, discopass)).read().strip('\n').strip()

if not os.path.exists(temp):
    os.makedirs(temp)

if mode == 1:
    f = open(iplist, "w")
    f.write(testsubnet)
    f.close()
elif mode == 2:
    shutil.copyfile(file,iplist)
elif mode == 3:
    os.system('/usr/tideway/bin/tw_upduser --active %s' % (discouser))
    os.system('/usr/tideway/bin/tw_query -u %s -p %s --no-headings %s > %s 2> %s' % (discouser, discopass, query, iplist, log))
else:
    print("Mode %s not recognised." % (mode))
    sys.exit(1)


curated = os.popen("nmap -n -sL -iL %s -oG - | awk '/^Host/{print $2}'" % (iplist)).read()
f = open(iplist, "w")
for line in curated.splitlines():
    f.write(line)
    f.write("\n")
f.close()

os.system('nmap -oX %s -p %s -n --host-timeout %s --script ssl-cert,ssl-enum-ciphers -iL %s > %s 2>&1' % (capture, ports, timeout, iplist, log))

for line in fileinput.FileInput(capture,inplace="1"):
    line = re.sub("(<!--.*)as: nmap.*?(-->)", r"\1\2", line)
    line = re.sub("(.*args=\")nmap.*?(\".*>)", r"\1\2", line)
    sys.stdout.write(line)

os.system('echo "_traversys" | gpg --yes --batch --quiet --passphrase-fd 0 -o %s -c %s' % (temp + "/ssl-out.gpg", capture))
os.remove(capture)

sys.exit(0)
