#!/bin/sh -e

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

for l in ${path}/*so* ; do
	echo -n "getting maps from "
	(echo $l | awk -F / '{print $NF}')
	${prefix}-nm $l | grep -e " [tT] " | grep -v " t L.L" | sed -e 's:^00000000::' > ./maps/${l##*/}.map
	${prefix}-objdump -d $l > ./dis/${l##*/}.dis
done
