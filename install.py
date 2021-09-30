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
import logging
import datetime
import getpass
import platform
import secrets
import re
import configparser
import py_compile

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
logging.basicConfig(level=logging.INFO, filename=logfile, filemode='w')
logger = logging.getLogger("getCert Installation")

pwd = os.getcwd()
libdir = (pwd + "/lib")
tpldir = (pwd + "/tpl")
ini = (pwd + "/config.ini")

os.system('clear')

instance = input('Please enter the IP address or URL of Discovery: ')
if not instance:
    msg = "No Discovery instance supplied! Please run the install script again."
    print(msg)
    logger.critical(msg)
    sys.exit(1)

## Get Discovery credential

token = input('Please enter your Discovery API token: ')
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

## Generate Passphrase

phrase = getpass.getpass(prompt='Set a GPG passphrase (or leave it blank for randomly generated one): ')
if not phrase:
    phrase = secrets.token_hex(32)
    print("You randomly generated passphrase is:",phrase)
    print("Store this safely, if you lose it you will have to commission a fresh installation.")

## Commission a lock file

pfile= libdir+"/."+instance.replace(".","_")
f=open(pfile, 'w')
f.write(token)
f.close()
vault = libdir+"/"+instance.replace(".","_")
msg = "Lock file commissioned: %s"%vault
logger.info(msg)
os.system('echo "%s" | gpg --yes --batch --quiet --passphrase-fd 0 -o %s -c %s' % (phrase, vault, pfile))
os.remove(pfile)

## Commission the key file

kfile= libdir+"/"+instance.replace(".","_")+".py"
f=open(kfile, 'w')
f.write("passphrase = '%s'"%phrase)
f.close()
msg = "Key file commissioned: %s"%kfile
logger.info(msg)
py_compile.compile(kfile)
os.remove(kfile)

## Read and Update Config

config = configparser.ConfigParser()
config.read(ini)
config.set('ENV', 'root', pwd)
with open(ini, 'w') as configfile:
    config.write(configfile)
    msg = "Config file updated with root: %s"%pwd
    logger.info(msg)

root = config.get('ENV', 'root')
logger.debug(root)

## Update TPL file

tplfile = open(tpldir + "/Traversys_getCert_Main.tpl").read()
msg = "Updating %s/Traversys_getCert_Main.tpl"%tpldir
logger.info(msg)
newtpl = re.sub(r'install_dir := ~INSTALLDIR~;', 'install_dir := \'%s\';' % (root), tplfile)
#tplfile = open(tpldir + "/Traversys_getCert_Main.tpl", 'w')
tplfile = open(tpldir + "/Traversys_getCert_Main_updated.tpl", 'w')
tplfile.write(newtpl)
tplfile.close()

## Deploy TPL

try:
    ku = disco.knowledge()
    msg = "Connected to Discovery Knowledge endpoint."
    logger.info(msg)
except:
    msg = "Error getting Knowledge from %s\n" % (instance)
    print(msg)
    logger.error(msg)
    sys.exit(1)

data = disco.data()
results = data.search("search Host")
print(results.ok)
print(results.content)

cg_Functions = ku.uploadKnowledge("getCert Functions","%s/Traversys_getCert_Functions.tpl"%tpldir)
print(cg_Functions.ok)
print(cg_Functions.content)
ku.uploadKnowledge("getCert Main","%s/Traversys_getCert_Main.tpl"%tpldir)
ku.uploadKnowledge("getCert","%s/Traversys_getCert.tpl"%tpldir)
ku.uploadKnowledge("getCert CMDB","%s/Traversys_getCert_CMDB_SI.tpl"%tpldir)
msg = "getCert Knowledge files uploaded."
logger.info(msg)

print("Patterns uploaded!")
print("You can set the cronjob with the 'cron.sh' script\n")

sys.exit(0)