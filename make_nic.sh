#!/bin/bash
set -ex

name="$1"
mac="$2"
ip="$3"

sudo ip link add "$name" type dummy
sudo ifconfig "$name" hw ether "C8:D7:4A:4E:47:$mac"
sudo ip addr add "192.168.1.$ip/24" brd + dev "$name" label "$name:0"
sudo ip link set dev "$name" up
ip a show dev "$name"
