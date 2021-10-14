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
import platform
import configparser
import time
import argparse

# Pip modules
import tideway
import dotenv

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

def upload(disco, pattern_name, tpl_path):
    pattern_file = "%s/%s"%(tpl_path,pattern_name)
    disco.uploadKnowledge(pattern_name,pattern_file)
    success = False
    while True:
        status = disco.getUploadStatus()
        if status.ok:
            if status.json()["processing"] == False:
                if status.json()["last_result"] == "success":
                    msg = "%s uploaded succesfully."%pattern_name
                    print(msg)
                    logger.info(msg)
                    success = True
                    break
                elif status.json()["last_result"] == "failure":
                    msg = "%s Upload failed.\n%s"%(pattern_name,status.json()["error"])
                    print(msg)
                    logger.error(msg)
                    break
                else:
                    msg = "There was some problem %s upload.\n%s\n%s"%(pattern_name,status.json()["last_result"],status.json()["messages"])
                    print(msg)
                    logger.error(msg)
                    break
        else:
            msg = "There was some problem attempting to get Knowledge Upload status.\n%s"%status
            print(msg)
            logger.error(msg)
            break
        print("Uploading %s."%pattern_name,end='\r')
        time.sleep(0.5)
        print("Uploading %s.."%pattern_name,end='\r')
        time.sleep(0.5)
        print("Uploading %s..."%pattern_name,end='\r')
        time.sleep(0.5)
        print("Uploading %s   "%pattern_name,end='\r')
        time.sleep(0.5)
        success = False
    return success

config = configparser.ConfigParser()
parser = argparse.ArgumentParser(description='getCert Utility',formatter_class=argparse.RawTextHelpFormatter)
parser.add_argument('--nokeys', dest='nokeys', action='store_true', required=False, help='Do no save authentication token.\n\n')
parser.add_argument('--nopatterns', dest='nopatterns', action='store_true', required=False, help='Do no upload Knowledge patterns.\n\n')
parser.add_argument('--debug', dest='debug', action='store_true', required=False, help='Run installation with debug logging.\n\n')

args = parser.parse_args()

pwd = os.getcwd()
libdir = (pwd + "/lib")
tpldir = (pwd + "/tpl")
logdir = (pwd + "/logs")
ini = (pwd + "/config.ini")
env = libdir+"/.env"

logfile = '%s/install_%s.log' % (logdir,str(datetime.date.today()))
if args.debug:
    logging.basicConfig(level=logging.DEBUG, filename=logfile, filemode='w')
else:
    logging.basicConfig(level=logging.INFO, filename=logfile, filemode='w')
logger = logging.getLogger("getCert Installer")

dotenv.load_dotenv(dotenv_path=env)

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

logger.info("Using API version%s"%apiver)

disco = tideway.appliance(instance,token,api_version=apiver)
msg = "API found on %s." % instance
logger.info(msg)
swagger = disco.swagger()

if swagger.ok:
    msg = "Successful API call to %s" % swagger.url
    logger.info(msg)
    if args.nokeys:
        msg = "Token not stored."
        print(msg)
        logger.info(msg)
    else:
        dotenv.set_key(env, "DISCOVERY_DEFAULT", token) # This is for the default/single instance
        tok_key = instance.replace(".","_").upper()
        try:
            os.environ['%s'%tok_key]
            logger.info("Token already exists for %s"%tok_key)
        except:
            logger.info("New token stored in env key for %s"%tok_key)
            dotenv.set_key(env, tok_key, token) # This is for multiple Discovery instances
else:
    msg = "ERROR: Problem with API, please refer to developer.\nReason: %s, URL: %s\n" % (swagger.reason, swagger.url)
    print(msg)
    logger.error(msg)
    sys.exit(1)

if apiver:
    disco = tideway.appliance(instance,token,api_version=apiver)
else:
    disco = tideway.appliance(instance,token)

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

## Deploy TPL

if args.nopatterns:
    msg = "No patterns uploaded."
    print(msg)
    logger.info(msg)
else:
    try:
        ku = disco.knowledge()
        msg = "Connected to Discovery Knowledge endpoint."
        logger.info(msg)
    except:
        msg = "Error getting Knowledge from %s\n" % (instance)
        print(msg)
        logger.error(msg)
        sys.exit(1)
    # Uploaded in order of this list
    tpl_names = [ "traversys_getCert_funcs.tpl", "traversys_getCert.tpl", "traversys_getCert_CMDB_si.tpl" ]
    for tpl_name in tpl_names:
        success = upload(ku, tpl_name, tpldir)
    if success:
        msg = "Uploads complete!"
        print(msg)
        logger.info(msg)
    else:
        msg = "Error: There was some problem with the TPL uploads, consult the log file!"
        print(msg)

sys.exit(0)