#!/bin/sh -e

gcc="bfin-linux-uclibc-gcc"
if ! ${gcc} -v > /dev/null 2>&1 ; then
	echo "bfin toolchain is not in PATH, please fix your PATH"
	exit 1
fi
prefix=${gcc%-gcc}

if [ -z "$1" ] ; then
	echo "need list of paths for maps"
	exit 1
fi

verbose=false
if [ "$1" = "-v" ] ; then
	shift
	verbose=true
fi
vecho() { ${verbose} && echo "$@" || :; }

for p in "$@" ; do
	vecho "Searching for ELFs in ${p}"
	for f in $(find "$@" -type f -print0 | xargs -0 file | grep ELF | sed -e 's|:.*||') ; do
		vecho "Generating map for ${f#${p}}"
		${prefix}-nm $f | grep -e " [tT] " | grep -v " t L.L" | sed -e 's:^00000000::' > ${f##*/}.map
	done
done
