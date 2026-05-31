#!/bin/bash
sudo nmap -sn -PS -p22,80,443 $1
