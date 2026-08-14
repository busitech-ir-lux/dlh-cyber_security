#!/bin/bash
sudo grep -Ei '^(rocommunity | rwcommunity)\s+public' /etc/snmp/snmpd.conf
