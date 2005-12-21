#!/bin/sh
./bfin_opcontrol --init
./bfin_opcontrol --setup
./bfin_opcontrol --start-daemon
./bfin_opcontrol --start
sleep 5
./bfin_opcontrol --dump
