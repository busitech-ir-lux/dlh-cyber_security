#!/bin/bash
user=$1
pass=$2
sudo useradd "$user" -p "$2"
