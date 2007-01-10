#!/bin/sh

./bfin_opcontrol --init
./bfin_opcontrol --setup
./bfin_opcontrol --start-daemon
sleep 3
./bfin_opcontrol --start
sleep 1500
./bfin_opcontrol --dump
SAMPLE_FILE=/var/lib/oprofile/samples/current/\{root\}/vmlinux/\{dep\}/\{root\}/vmlinux/TOTAL_BRANCH.500.1.all.all.all
if test -e $(SAMPLE_FILE); then echo "oprofile_succ" ; fi;
