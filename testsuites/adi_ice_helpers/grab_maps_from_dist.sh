#!/bin/sh

dist=$1
if [ -z "$dist" -o ! -d "$dist" ] ; then
        echo "Usage: $0 <path to distribution source>"
        exit 1
fi


kernel=${dist}/linux-2.6.x/
user=${dist}/user/
libs=${dist}/lib/
staging=${dist}/staging
out_dis=${PWD}/dis
out_maps=${PWD}/maps

mkdir -p ${out_dis}
mkdir -p ${out_maps}

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

for module in $(cat ./modules.list) vmlinux
do
	if [ -f ${out_maps}/${module}.ko.text.map -a -f ${out_dis}/${module}.ko.text.dis ] ; then 
		echo  already processed module $module
		continue
	fi
	echo finding module $module
	file=`find ${kernel} -name ${module}.ko`
	if [ -z ${file} ] ; then
        	file=`echo ${module} | sed 's/_/-/g'`
		file=`find ${kernel} -name ${file}.ko`
	fi
	if [ -z ${file} ] ; then
		file=`find ${kernel} -name  ${module}`
	fi

	if [ -z ${file} ] ; then
		echo "Could not find ${module}.ko"
	else
		for section in $(bfin-uclinux-objdump -d $file  | grep Disassembl | awk '{print $NF}' | sed s/://)
		do
  			(bfin-uclinux-objdump -d $file  | sed -n "/section ${section}/,/Disassembly of section/ p" | grep ">:" | sed s/\>:// | sed s/\<// ) > ${out_maps}/${module}.ko${section}.map
			bfin-uclinux-objdump -j ${section} -d $file > ${out_dis}/${module}.ko${section}.dis
		done
	fi
done

for app in $(cat user.list | awk '{print $6}' | awk -F "[/ ]" '{print $NF }')
do
	if [ -f ${out_maps}/${app}.map -a -f ${out_dis}/${app}.dis ] ; then
		echo already processed ${app}
		continue
	fi
	if [ "$app" = "busybox" ] ; then
		app="busybox_unstripped"
	fi
	echo finding application $app
	files=`find -L ${user} ${libs} ${staging} -type f -name ${app} 2>/dev/null`
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
		bfin-uclinux-nm -n ${file} | grep " [wWtT] " | grep "^[0-9a-f]" | sort -k 2 > ${out_maps}/${app}.map
		bfin-uclinux-objdump -d ${file} > ${out_dis}/${app}.dis
	        foo=`egrep \<\.plt\>: ${out_dis}/${app}.dis`
		if [ -n "$foo" ] ; then
			echo $foo | sed 's/ / t __/' | sed 's/[.<>:]//g' >> ${out_maps}/${app}.map
		fi

	done
	if [ ! -f ${out_maps}/${app}.map ] ; then
		echo Could not find unstripped version of ${app}
	fi
	
done
