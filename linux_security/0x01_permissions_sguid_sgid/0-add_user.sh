#!/bin/bash
sudo useradd "$1"
sudo echo $2 | passwd --stdin $1
