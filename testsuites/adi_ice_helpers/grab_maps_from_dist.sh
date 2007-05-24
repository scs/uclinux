#!/bin/sh

dist=$1
if [ -z "$dist" -o ! -d "$dist" ] ; then
        echo "Usage: $0 <path to distribution source>"
        exit 1
fi


kernel=${dist}/linux-2.6.x/
user=${dist}/user/
libs=${dist}/lib/

if [ ! -r "$kernel/arch/blackfin/Kconfig" ] ; then
	echo "Usage: $0 <path to distribution source>"
	echo "Can't find kernel source in $kernel"
	exit 1
fi

if [ ! -d $user ] ; then
        echo "Usage: $0 <path to distribution source>"
        echo "Can't find userspace source in $user"
        exit 1
fi



if [ ! -f ./modules.list -o ! -f ./user.list ] ; then
	echo "Must run grab_maps_from_board first"
	exit 1
fi

for module in $(cat ./modules.list)
do
	[ ! -f ${module}.ko.map ] || continue
	file=`find ${kernel} -name ${module}.ko`
	if [ -z ${file} ] ; then
        	file=`echo ${module} | sed 's/_/-/g'`
		file=`find ${kernel} -name ${file}.ko`
	fi

	if [ -z ${file} ] ; then
		echo "Could not find ${module}.ko"
	else
		bfin-uclinux-nm -n ${file} | grep " [tT] " > ${module}.ko.map
	fi
done

for app in $(cat user.list | awk '{print $6}' | awk -F "[/ ]" '{print $NF }')
do
	[ ! -f ${app}.map ] || continue
	if [ "$app" = "busybox" ] ; then
		app="busybox_unstripped"
	fi
	files=`find -L ${user} ${libs} -type f -name ${app}`
	for file in ${files}
	do
		[ ! -r ${app}.map ] || continue
		link=`file ${file} | grep "symbolic link"`
		if [ -n "$link" ] ; then
			link=`readlink ${file}`
			file=`echo ${file} | sed s/${app}// `
			file=${file}${link}
		fi
		elf=`file ${file} | grep "ELF 32-bit LSB"`
		[ -n "$elf" ] || continue
		bfin=`bfin-uclinux-readelf -h ${file} | grep Blackfin`
		[ -n "$bfin" ] || continue
		strip=`file ${file} | grep "not stripped"`
		[ -n "$strip" ] || continue
		if [ "$app" = "busybox_unstripped" ] ; then
			app="busybox"
		fi
		bfin-uclinux-nm -n ${file} | grep " [tT] " > ${app}.map
	done
	if [ ! -f ${app}.map ] ; then
		echo Could not find unstripped version of ${app}
	fi
	
done
