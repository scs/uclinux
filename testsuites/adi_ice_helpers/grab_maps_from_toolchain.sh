#!/bin/sh

gcc="$1"
if [ -z "$gcc" ] ; then
	gcc="bfin-linux-uclibc-gcc"
fi
if ! ${gcc} -v > /dev/null 2>&1 ; then
	echo "bfin toolchain is not in PATH, please fix your PATH"
	exit 1
fi
prefix=${gcc%-gcc}

libc=$($gcc -print-file-name=libc.a)
path="${libc%/*}/../../lib"
mkdir -p ./maps
mkdir -p ./dis

for l in ${path}/*so* ; do
	echo -n "getting maps from "
	(echo $l | awk -F / '{print $NF}')
	${prefix}-nm $l | grep -e " [wWtT] " | grep -v " t L.L" | grep "^[0-9a-f]" | sed -e 's:^00000000::' | sort -k 2 > ./maps/${l##*/}.map
	${prefix}-objdump -d $l > ./dis/${l##*/}.dis
	foo=`egrep \<\.plt\>: ./dis/${l##*/}.dis`
	if [ -n "$foo" ] ; then
		echo $foo | sed 's/ / t __/' | sed 's/[.<>:]//g' >> ./maps/${l##*/}.map
	fi
done
