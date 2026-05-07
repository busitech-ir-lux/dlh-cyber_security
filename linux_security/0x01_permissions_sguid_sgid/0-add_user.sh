#!/bin/bash
# This file will add a user and sets a password based on input data
sudo useradd "$1" -p "$2"
