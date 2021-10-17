#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright (c) 2021 Traversys Limited
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
# Setup script for Traversys getCert
#

import configparser
import argparse
import socket
import os
import shutil
import signal
import sys
import datetime
import logging
import dotenv
import glob

config = configparser.ConfigParser()
parser = argparse.ArgumentParser(description='getCert standalone install',formatter_class=argparse.RawTextHelpFormatter)
parser.add_argument('--install', dest='install', action='store_true', required=False, help='Install getCert (with TPL upload).\n\n')
parser.add_argument('--dashboards', dest='dashboards', action='store_true', required=False, help='Install dashboards and reporting (appliance).\n\n')
parser.add_argument('--debug', dest='debug', action='store_true', required=False, help='Run installation with debug logging.\n\n')
parser.add_argument('--replace', dest='replace', action='store_true', required=False, help='Overwrite files if they already exist.\n\n')

args = parser.parse_args()

pwd = os.getcwd()
libdir = os.path.join(pwd,"lib")
tpldir = os.path.join(pwd,"tpl")
logdir = os.path.join(pwd,"logs")
xmldir = os.path.join(pwd,"xml")
ini = os.path.join(pwd,"config.ini")
env = os.path.join(libdir,".env")

logfile = '%s/install_%s.log' % (logdir,str(datetime.date.today()))
if args.debug:
    logging.basicConfig(level=logging.DEBUG, filename=logfile, filemode='w')
else:
    logging.basicConfig(level=logging.INFO, filename=logfile, filemode='w')
logger = logging.getLogger("getCert Installer")

logger.debug("Working directory is: %s"%pwd)

def install(extensions,from_dir,to_dir):
    logger.debug("EXTENSIONS: %s"%extensions)
    logger.debug("FROM DIR: %s"%from_dir)
    logger.debug("TO DIR: %s"%to_dir)
    for files in extensions:
        to_move = glob.iglob(os.path.join(from_dir, files))
        for f in to_move:
            logger.debug("FILE F: %s"%f)
            filename = os.path.basename(f)
            existing = os.path.join(to_dir,filename)
            logger.debug("DEST: %s"%existing)
            if os.path.exists(existing):
                if args.replace:
                    shutil.move(f, existing)
                    logger.debug("Replaced %s"%(existing))
                else:
                    logger.warn("Existing file was not overwritten %s"%existing)
            else:
                shutil.move(f, to_dir)
                logger.debug("Installed %s in %s"%(f,to_dir))

for path in [ libdir, tpldir, logdir, xmldir ]:
    if not os.path.exists(path):
        os.makedirs(path)

dotenv.load_dotenv(dotenv_path=env)

os.system('clear')

# Prevent Interrupt
hold = signal.signal(signal.SIGINT, signal.SIG_IGN)

install([ "*.tpl" ],pwd,tpldir)
install([ "*.xml", "*.dash" ],pwd,xmldir)
install([ "*.cron", "*.sh" ],pwd,libdir)

if args.install:
    config.read(ini)
    config.set('ENV', 'root', pwd)
    with open(ini, 'w') as configfile:
        config.write(configfile)
    root = config.get('ENV', 'root')
    appliance = socket.gethostname()
    instance = input('Please enter the IP address or URL of Discovery (default=%s): '%appliance)
    if not instance:
        instance = appliance
        msg = "Instance set to %."%instance
        logger.info(msg)
    os.system("%s/install --target %s"%(pwd,instance))

if args.dashboards:
    print("Dashboard deployment will temporily halt and reboot appliance services, do you want to continue?")
    yep = input('Enter "Y" to continue: ').lower().strip()
    if not yep == 'y':
        logger.info("User opted not to continue.")
        sys.exit(0)
    # Stop the appserver first
    os.system('/usr/tideway/bin/tw_service_control --stop appserver')
    # Copy dashboards
    os.system('cp %s/traversys_00_reports.xml /usr/tideway/data/custom/reports' % (xmldir))
    os.system('cp %s/traversys_getCert.dash /usr/tideway/etc/dashboards' % (xmldir))
    # Restart the app server
    os.system('/usr/tideway/bin/tw_service_control --start appserver')
    # Makeself script seems to bork this file into Windows CRLF (possibly because run in WSL?)
    # So we have recreate the file with Python
    with open('%s/cron.sh'%libdir) as original:
        lines = [line.replace('\r\n', '\n') for line in original]
    with open('%s/cron.sh'%libdir, 'w') as newer:
        newer.writelines(lines)
    os.chdir(libdir)
    os.system('./cron.sh')

# Restore Interrupt
signal.signal(signal.SIGINT, hold)
print("All done!")
sys.exit(0)
