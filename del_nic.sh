#!/bin/bash
set -ex

name=$1
ip=$2

sudo ip addr del "192.168.1.$ip/24" brd + dev "$name" label "$name:0"
sudo ip link delete "$name" type dummy
