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
# Setup script for Traversys getCert
#

import os
import sys
import shutil
import glob
import argparse
import configparser
import logging
import dotenv
import datetime

config = configparser.ConfigParser()
parser = argparse.ArgumentParser(description='getCert Utility',formatter_class=argparse.RawTextHelpFormatter)
parser.add_argument('--debug', dest='debug', action='store_true', required=False, help='Run installation with debug logging.\n\n')

args = parser.parse_args()

pwd = os.getcwd()
parent = os.path.dirname(pwd)
libdir = (parent + "/lib")
tpldir = (parent + "/tpl")
logdir = (parent + "/logs")
xmldir = (parent + "/xml")
ini = (parent + "/config.ini")
env = libdir+"/.env"
dist = (pwd + "/dist")
pkg = (pwd + "/package")

logfile = '%s/build_%s.log' % (logdir,str(datetime.date.today()))
if args.debug:
    logging.basicConfig(level=logging.DEBUG, filename=logfile, filemode='w')
else:
    logging.basicConfig(level=logging.INFO, filename=logfile, filemode='w')
logger = logging.getLogger("getCert Installer")

dotenv.load_dotenv(dotenv_path=env)
os.system('clear')

### Copy over source files

license = (parent + "/LICENSE")
readme = (parent + "/README")
version = (parent +  "/VERSION")
files = [ "*.ini", "*.cron", "*.sh", "*.tpl" ]
py_files = [ "*.py" ]

# Copy from current/parent folder
for dir in [ parent, pwd, tpldir, xmldir ]:
    for f in files:
        to_copy = glob.iglob(os.path.join(dir, f))
        for cf in to_copy:
            if os.path.isfile(cf):
                logger.info("Copying %s to %s"%(cf,pkg))
                shutil.copy2(cf,pkg)

# Copy metadata files
for file in [ license, readme, version ]:
    if os.path.isfile(file):
        logger.info("Copying %s to %s"%(file,pkg))
        shutil.copy2(file,pkg)

# Compile python files for execution on remote
for p in py_files:
    b_files = glob.iglob(os.path.join(parent, p))
    for py_file in b_files:
        if os.path.isfile(py_file):
            logger.info("Compiling %s "%(py_file))
            os.system("pyinstaller --onefile %s"%py_file)

# Compile setup
logger.info("Compiling setup file")
os.system("pyinstaller --onefile %s/setup.py"%pwd)

# Copy distributable binaries
if os.path.exists(dist):
    logger.info("Distribution dir created: %s"%(dist))
    bins = glob.iglob(os.path.join(dist, "*"))
    for bf in bins:
        if os.path.isfile(bf):
            logger.info("Copying %s to %s"%(bf,pkg))
            shutil.copy2(bf,pkg)

### Compile Distributable Binary

os.system("makeself --notemp --target ./Traversys/getCert ./package ./traversys_getcert.run 'getCert SSL Certificate Discovery from Traversys' ./setup")

sys.exit(0)
