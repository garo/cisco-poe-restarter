Tool to restart poe devices connected to Cisco switches
=======================================================

This tool uses SNMP to loop over a set of switches, finds all interfaces which description contains a magic word and then toggles the interface power-over-ethernet down for a few seconds and then back on.

Prerequisites: "pip install pysnmp" and Python 3.

Configuration
=============

See poe-restarter.py for instructions.

Usage
=====

Once the configuration has been set populate a list of switches into a .txt file, one ip (or hostname which resolvs to an ip) per line and then run the tool as "poe-restarter switches.txt". Other option is to pass a single ip from the command line: "poe-restarter 10.2.3.4"

Tested on
=========

 - Cisco 9300 Catalyst