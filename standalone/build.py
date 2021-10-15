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
import hashlib
import configparser

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
#########

pwd = os.getcwd()
source = (pwd + "/source")
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
