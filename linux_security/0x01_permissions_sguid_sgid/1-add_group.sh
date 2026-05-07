#!/bin/bash
sudo addgroup $1
sudo chown :$1 $2
sudo chmod g+xr $2
