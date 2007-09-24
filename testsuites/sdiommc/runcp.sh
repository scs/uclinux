#!/bin/sh

SUBDIR=`ls / | grep -v mnt | grep -v proc | grep -v sys`

for i in $SUBDIR
do
	cp -ar $i /mnt/rootfs
	echo "copy $i finish"
done

mkdir /mnt/rootfs/mnt
mkdir /mnt/rootfs/proc
mkdir /mnt/rootfs/sys

echo "copy rootfs done"
