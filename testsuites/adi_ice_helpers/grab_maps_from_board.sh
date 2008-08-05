#!/bin/sh

ip=$1
if [ -z "$ip" ] ; then
	echo "Usage: $0 <IP of board>"
	exit 1
fi

rsh="rsh -l root $ip"
rcp="rcp root@$ip:"

$rsh cat /proc/kallsyms | grep " [Tt] " > System.list
$rsh cat /proc/maps | grep "x[ps] " | awk 'NF > 5' > user.list
$rsh cat /proc/sram | grep -v NULL | sed -n "/--- L1 Instruction/,// p" | grep -v " L1 Instruction" | sed "s/-/ /" > l1_sram.list
${rsh} lsmod | awk '{print $1}' | grep -v Module > modules.list
${rsh} ps | grep -v "\[.*\]" | grep -v PID | sed 's/ < / /g' | awk '{print $1 " " $5 }' | awk -F "[/ ]" '{print $NF" " $1}' | sed 's/^-//' > pid.list
