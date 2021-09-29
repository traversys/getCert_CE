#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2021 Traversys Limited
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
# Install script for Traversys getCert
#

# Python Built-in
import os
import sys
import shutil
import glob
import stat
import hashlib
import logging
import datetime
import getpass
import platform

# Pip modules
import tideway

def ping(instance):
    current_os = platform.system().lower()
    if current_os == "windows":
        parameters = "-n 1 -w 2"
        null = "$null"
    elif current_os == "Linux":
        parameters = "-c 1 -w2"
        null = "/dev/null"
    else: # Mac
        parameters = "-c 1 -i2"
        null = "/dev/null"
    exit_code = os.system(f"ping {parameters} {instance} > {null} 2>&1")
    if os.path.exists("$null"):
        # Windows outputs to a '$null' file instead of Null
        os.remove("$null")
    return exit_code

def api_version(tw):
    about = tw.about()
    if about.ok:
        version = about.json()['api_versions'][-1]
        return(about, version)

logfile = 'install_%s.log' % ( str(datetime.date.today()))
logging.basicConfig(level=logging.INFO, filename=logfile, filemode='w',force=True)
logger = logging.getLogger("getCert Installation")

os.system('clear')

instance = input('Please enter the IP address or URL of Discovery: ')
if not instance:
    msg = "No Discovery instance supplied! Please run the install script again."
    print(msg)
    logger.critical(msg)
    sys.exit(1)

token = getpass.getpass(prompt='Please enter your Discovery API token: ')
if not token:
    msg = "No token supplied! Please run the install script again."
    print(msg)
    logger.critical(msg)
    sys.exit(1)

msg = "\nChecking Discovery API on %s..." % instance
print(msg)
logger.info(msg)

exit_code = ping(instance)
if exit_code == 0:
    disco = tideway.appliance(instance,token)
else:
    msg = "%s not found\nExit Code: %s"%(instance,exit_code)
    print(msg)
    logger.critical(msg)
    sys.exit(1)

try:
    about, apiver = api_version(disco)
except OSError as e:
    msg = "Error connecting to %s\n%s\n" % (instance,e)
    print(msg)
    logger.error(msg)
    sys.exit(1)

msg = "About: %s\n"%about.json()
logger.info(msg)

print("Using API version",apiver,"\n")

disco = tideway.appliance(instance,token,api_version=apiver)
msg = "API found on %s." % instance
logger.info(msg)
swagger = disco.swagger()

if swagger.ok:
    msg = "Successful API call to %s" % swagger.url
    logger.info(msg)
else:
    msg = "ERROR: Problem with API version, please refer to developer.\nReason: %s, URL: %s\n" % (swagger.reason, swagger.url)
    print(msg)
    logger.error(msg)
    sys.exit(1)

if apiver:
    disco = tideway.appliance(instance,token,api_version=apiver)
else:
    disco = tideway.appliance(instance,token)

try:
    twvault = disco.vault()
except:
    msg = "Error getting Valut from %s\n" % (instance)
    print(msg)
    logger.error(msg)
    sys.exit(1)

## Get Discovery credential

## Store in encrypted file

## Set tpl install location

## Upload to Discovery

pwd = os.getcwd()
source = (pwd)
makeself = (pwd + "/makeself")
getcert = (makeself + "/Traversys/getCert")
dist = (makeself + "/dist")

if not os.path.exists(getcert):
    os.makedirs(getcert)

binaries = [ "*.py" ]
files = [ "*.tpl", "*.ini", "*.sh", "*.txt", "*.xml", "*.cron", "*.dash" ]
pys = [ "getcert.py", "unlocker.py", "license_check.py", "setup.py" ]

os.system('clear')

### Copy over source files

license = (source + "/LICENSE")
readme = (source + "/README")
version = (source +  "/VERSION")

if os.path.isfile(license):
    shutil.copy2(license,getcert)

if os.path.isfile(readme):
    shutil.copy2(readme,getcert)

if os.path.isfile(version):
    shutil.copy2(version,getcert)

for f in files:
    source_files = glob.iglob(os.path.join(source, f))
    for sf in source_files:
        if os.path.isfile(sf):
            shutil.copy2(sf,getcert)

for b in binaries:
    bin_files = glob.iglob(os.path.join(source, b))
    for bf in bin_files:
        if os.path.isfile(bf):
            shutil.copy2(bf,makeself)

### Compile Binaries

#os.system("python3 -m py_compile %s/hide.py" % (makeself))
#hider = (makeself +  "/hide.pyc")
#if os.path.isfile(hider):
#    os.chmod(hider, 0o755)
#    shutil.copy2(hider,getcert + "/hide")

os.chdir(makeself)

for p in pys:
    py_file = (makeself +  "/" + p)
    if os.path.isfile(py_file):
       os.system("pyinstaller --onefile %s" % (py_file))

if os.path.exists(dist):
    bin_pys = glob.iglob(os.path.join(dist, "*"))
    for bf in bin_pys:
        if os.path.isfile(bf):
            shutil.copy2(bf,getcert)

### Compile Distributable Binary

os.system("makeself-2.4.0/makeself.sh --notemp ./Traversys ./traversys_getcert.run 'getCert SSL Certificate Discovery from Traversys' ./getCert/setup")

with open(getcert + "/getcert",'rb') as gc:
    data = gc.read()
    md5get = hashlib.md5(data).hexdigest()
    print("getcert MD5SUM: " + md5get + "\n")

sys.exit(0)
