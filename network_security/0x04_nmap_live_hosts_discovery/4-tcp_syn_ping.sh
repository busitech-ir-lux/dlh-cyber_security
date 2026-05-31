#!/bin/bash
sudo nmap -sn -sS -p22,80,443 $1
