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
# 2021-10-03 : WMF : Updated to a stand-alone script using API calls for Discovery interaction.
#

# Standard Packages
import os
import sys
import re
import fileinput
import datetime
import shutil
import csv
import logging
import configparser
import argparse
from argparse import RawTextHelpFormatter
import secrets

# Pip Packages
import tideway
import dotenv

def csvFile(data, heads, args):
    data.insert(0, heads)
    with open(args.file, 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerows(data)
    msg = "Results written to %s" % args.file
    print(msg)
    logger.info(msg)

logfile = 'getCert_%s.log' % ( str(datetime.date.today()))
logging.basicConfig(level=logging.DEBUG, filename=logfile, filemode='w')
logger = logging.getLogger("getCert")

config = configparser.ConfigParser()

parser = argparse.ArgumentParser(description='getCert Utility',formatter_class=RawTextHelpFormatter)
parser.add_argument('-a', '--instance', dest='instance',  type=str, required=False, help='The target Discovery system.\n\n', metavar='<IP or URL used in install script>')
parser.add_argument('-c', '--config', dest='config',  type=str, required=False, help='The location of the config.ini file.\n\n', metavar='<config.ini>')
parser.add_argument('-l', '--logfile', dest='logfile',  type=str, required=False, help='Log standard output of scan.\n\n', metavar='<logfile>')

args = parser.parse_args()

instance = args.instance
ini = args.config

if not ini:
    pwd = os.getcwd()
    ini = pwd+"/config.ini"

# Read config file
cfexists = os.path.isfile(ini)
if not cfexists:
    print("Config file missing! Cannot continue.")
    sys.exit(1)

config.read(ini)
root = config.get('ENV', 'root')
temp = config.get('ENV', 'temp')
iplist = config.get('ENV', 'iplist')
mode = int(config.get('MODE', 'mode'))
testsubnet = config.get('TEST_SUBNET', 'testsubnet')
file = config.get('LIST_OF_IPS', 'file')
query = config.get('DISCO_QUERY', 'query')
timeout = config.get('TIMEOUT', 'timeout')
ports = config.get('PORTS', 'ports')
date = datetime.datetime.now()
libdir = root+"/lib"
env = libdir+"/.env"

dotenv.load_dotenv(dotenv_path=env)

if not instance:
    tok_key = 'DISCOVERY_DEFAULT'
else:
    tok_key = instance.instance.replace(".","_").upper()
    
token = os.environ[tok_key]
capture = temp+"/%s.xml"%tok_key

if not os.path.exists(temp):
    os.makedirs(temp)

if mode == 1:
    f = open(iplist, "w")
    f.write(testsubnet)
    f.close()
elif mode == 2:
    shutil.copyfile(file,iplist)
elif mode == 3:
    disco = tideway.appliance(instance,token)
    data = disco.data()
    results = []
    try:
        results = data.search_bulk(query,limit=500)
        logger.debug(results)
    except Exception as e:
        msg = "Not able to make api call.\nQuery: %s\nException: %s" %(query,e.__class__)
        print(msg)
        logger.error(msg)
    if len(results) > 0:
        results.pop(0) # Get rid of header
        with open(iplist, 'w', newline='') as file:
            writer = csv.writer(file)
            writer.writerows(results)
            msg = "Results written to %s" % iplist
            print(msg)
            logger.info(msg)
    else:
        msg = "No results found!\n%s"%results
        print(msg)
        logger.warning(msg)
        sys.exit(1)
else:
    msg = "Mode %s not recognised."%mode
    print(msg)
    logger.critical(msg)
    sys.exit(1)

curated = os.popen("nmap -n -sL -iL %s -oG - | awk '/^Host/{print $2}'" % (iplist)).read()
f = open(iplist, "w")
for line in curated.splitlines():
    f.write(line)
    f.write("\n")
f.close()

if args.logfile:
    os.system('nmap -oX %s -p %s -n --host-timeout %s --script ssl-cert,ssl-enum-ciphers -iL %s > %s 2>&1' % (capture, ports, timeout, iplist, args.logfile))
else:
    os.system('nmap -oX %s -p %s -n --host-timeout %s --script ssl-cert,ssl-enum-ciphers -iL %s > /dev/null' % (capture, ports, timeout, iplist))

for line in fileinput.FileInput(capture,inplace="1"):
    line = re.sub("(<!--.*)as: nmap.*?(-->)", r"\1\2", line)
    line = re.sub("(.*args=\")nmap.*?(\".*>)", r"\1\2", line)
    sys.stdout.write(line)

phrase = secrets.token_hex(32)
print("Randomly generated passphrase is:",phrase)

os.system('echo "%s" | gpg --yes --batch --quiet --passphrase-fd 0 -o %s -c %s' % (phrase, temp + "/%s.gpg"%tok_key, capture))
os.remove(capture)

## Send event to Discovery

sys.exit(0)
