#!/bin/sh

ip=$1
if [ -z "$ip" ] ; then
	echo "Usage: $0 <IP of board>"
	exit 1
fi

rsh="rsh -l root $ip"

$rsh cat /proc/kallsyms | grep " [Tt] " > System.map
$rsh cat /proc/maps | grep "x[ps] " | awk 'NF > 5' > user.map
