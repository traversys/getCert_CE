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
import socket
import os
import getpass
import re
import signal
import subprocess
import time
import sys

def cleanup(root):
    os.remove(root + "/Traversys_getCert_Functions.tpl")
    os.remove(root + "/Traversys_getCert_Main.tpl")
    os.remove(root + "/Traversys_getCert.tpl")

os.system('clear')

# Prevent Interrupt
hold = signal.signal(signal.SIGINT, signal.SIG_IGN)

### Read and Update Config ###

config = configparser.ConfigParser()

### Setup root dir ###

pwd = os.getcwd()
cwd = (pwd + "/getCert")
ini = (cwd + "/config.ini")
config.read(ini)
config.set('ENV', 'root', cwd)
with open(ini, 'w') as configfile:
    config.write(configfile)

root = config.get('ENV', 'root')
appliance = socket.gethostname()

### Verify this is an Appliance ###

cluster = os.system('systemctl is-active cluster > /dev/null')
fs = os.system('df /usr/tideway > /dev/null')

if cluster == 0 and fs == 0:
    print("Appliance: %s" % (appliance))
else:
    print("Installing on none Discovery Appliance!")
    cleanup(root)
    os.remove(root + "/traversys_00_reports.xml")
    os.remove(root + "/traversys_getCert.dash")
    print("All done! You will need to configure crontab manually.")
    print("Ensure that you install the full getCert package on an appliance and configure to use this host.")
    sys.exit(0)

### Get Appliance Version ###
version = re.search("^(\d+)\.", os.environ['ADDM_VERSION']).group(1)

### Update TPL file ###

tplfile = open(root + "/Traversys_getCert_Main.tpl").read()
newtpl = re.sub(r'install_dir := ~INSTALLDIR~;', 'install_dir := \'%s\';' % (root), tplfile)
tplfile = open(root + "/Traversys_getCert_Config.tpl", 'w')
tplfile.write(newtpl)
tplfile.close()

### Start Warning ###

print("This install will temporily halt and reboot appliance services, do you want to continue?")
yep = input('Enter "Y" to continue: ').lower().strip()
if not yep == 'y':
    print("Cleaning up, please run the install script again when ready.")
    cleanup(root)
    sys.exit(1)

### Obtain Login Details ###

login = input('Please enter your appliance login: ')
if not login:
    print("ERROR: You must enter a system user login! Please run the install script again.")
    cleanup(root)
    sys.exit(1)

passwd = getpass.getpass(prompt='Please enter your appliance password: ')
if not passwd:
    print("ERROR: No password supplied! Please run the install script again.")
    cleanup(root)
    sys.exit(1)

### Test Access ###

test = os.system('/usr/tideway/bin/tw_pattern_management -u %s -p %s --list-uploads > /dev/null' % (login, passwd))
if test == 0:
    print("Login details confirmed.")
else:
    print("Login details failed! Please run the install script again.")
    cleanup(root)
    sys.exit(1)

### Deploy TPL and Dashboards ###

# Stop the appserver first
os.system('/usr/tideway/bin/tw_service_control --stop appserver')

os.system('/usr/tideway/bin/tw_pattern_management -u %s -p %s --install-activate %s/Traversys_getCert_Functions.tpl' % (login, passwd, root))
os.system('/usr/tideway/bin/tw_pattern_management -u %s -p %s --install-activate %s/Traversys_getCert_Config.tpl' % (login, passwd, root))
os.system('/usr/tideway/bin/tw_pattern_management -u %s -p %s --install-activate %s/Traversys_getCert.tpl' % (login, passwd, root))

os.system('cp %s/traversys_00_reports.xml /usr/tideway/data/custom/reports' % (root))
os.system('cp %s/traversys_getCert.dash /usr/tideway/etc/dashboards' % (root))

# Restart the app server
os.system('/usr/tideway/bin/tw_service_control --start appserver')

### Tidy Up ###

cleanup(root)

# Restore Interrupt
signal.signal(signal.SIGINT, hold)

print("All done!")
print("You can set the cronjob with the 'cron.sh' script\n")

sys.exit(0)
