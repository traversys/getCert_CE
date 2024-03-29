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
import secrets
from pprint import pprint
import ipaddress

# Pip Packages
import tideway
import dotenv

def ip_filter(ip):
    try:
        address = ipaddress.ip_address(ip)
        if isinstance(address, ipaddress.IPv4Address):
            return ip
        else:
            return None
    except:
        return None

config = configparser.ConfigParser()
parser = argparse.ArgumentParser(description='getCert Utility',formatter_class=argparse.RawTextHelpFormatter)
parser.add_argument('-a', '--instance', dest='instance',  type=str, required=True, help='The target Discovery system.\n\n', metavar='<IP or URL used in install script>')
parser.add_argument('-c', '--config', dest='config',  type=str, required=False, help='The location of the config.ini file.\n\n', metavar='<config.ini>')
parser.add_argument('-d', '--debug', dest='debug', action='store_true', required=False, help='Run in debug mode.\n\n')

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
logs = config.get('ENV', 'logs')
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

logfile = '%s/getCert_%s.log' % (logs,str(datetime.date.today()))
if args.debug:
    logging.basicConfig(level=logging.DEBUG, filename=logfile, filemode='w')
else:
    logging.basicConfig(level=logging.INFO, filename=logfile, filemode='w')
logger = logging.getLogger("getCert")

dotenv.load_dotenv(dotenv_path=env)

tok_key = instance.replace(".","_").upper()
if not tok_key:
    msg = "Not able to find the token for %s, using DISCOVERY_DEFAULT..."%instance
    print(msg)
    logger.warning(msg)
    tok_key = 'DISCOVERY_DEFAULT'

token = os.environ[tok_key]
capture = temp+"/%s.xml"%tok_key

if not os.path.exists(temp):
    os.makedirs(temp)

disco = tideway.appliance(instance,token)

if mode == 1:
    f = open(iplist, "w")
    f.write(testsubnet)
    f.close()
elif mode == 2:
    shutil.copyfile(file,iplist)
elif mode == 3:
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

for line in fileinput.input(iplist,inplace=True):
    # filter out IPv6 addresses until I can be arsed to accomodate them. Who is using IPv6 yet?
    ipv4 = ip_filter(line)
    if not ipv4:
        print(line, end="")

curated = os.popen("nmap -n -sL -iL %s -oG - | awk '/^Host/{print $2}'" % (iplist)).read()
f = open(iplist, "w")
for line in curated.splitlines():
    f.write(line)
    f.write("\n")
f.close()

if args.debug:
    os.system('nmap -oX %s -p %s -n --host-timeout %s --script ssl-cert,ssl-enum-ciphers -iL %s > %s 2>&1' % (capture, ports, timeout, iplist, logfile))
else:
    os.system('nmap -oX %s -p %s -n --host-timeout %s --script ssl-cert,ssl-enum-ciphers -iL %s > /dev/null' % (capture, ports, timeout, iplist))

for line in fileinput.FileInput(capture,inplace="1"):
    line = re.sub("(<!--.*)as: nmap.*?(-->)", r"\1\2", line)
    line = re.sub("(.*args=\")nmap.*?(\".*>)", r"\1\2", line)
    sys.stdout.write(line)

phrase = secrets.token_hex(32)
logger.debug("Randomly generated passphrase is: %s"%phrase)

os.system('echo "%s" | gpg --yes --batch --quiet --passphrase-fd 0 -o %s -c %s' % (phrase, temp + "/%s.gpg"%tok_key, capture))
if args.debug:
    pass
else:
    os.remove(capture)

event = {
            "source": "getCert",
            "type": "cert_scan",
            "params": {
                "phrase":"%s"%phrase,
                "file":"%s/%s.gpg"%(temp,tok_key)
                }
        }
        
## Send event to Discovery
events = disco.events()
try:
    posted = events.status(event)
    logger.info("Event sent to %s:\n%s"%(instance,posted.text))
except:
    msg = "Failed to post even to %s\n%s"%(instance,event)
    print(msg)
    logger.critical(msg)

sys.exit(0)
