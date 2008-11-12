#!/bin/bash

set -e

has() { [[ " ${*:2} " == *" $1 "* ]] ; }

v=
vecho() { [ -z "$v" ] || echo "$*" ; }

[ -n "${ROMFSDIR}" ] || exit 1

if ! scanelf -V > /dev/null ; then
	echo "ERROR: you do not have pax-utils installed"
	exit 1
fi

cd "${ROMFSDIR}"
libs=$(scanelf -F'%n#f' -qR bin sbin usr | sed 's:[, ]:\n:g' | sort -u)
cd lib

addlibs() {
	newlibs=$( (echo $libs; scanelf -F'%n#f' -qR ${libs}) | sed 's:[, ]:\n:g' | sort -u)
	newlibs=$(echo $newlibs)
	[ "$newlibs" != "$libs" ] || return 0
	libs=$newlibs
	addlibs
}
addlibs

(
find . -maxdepth 1 -type l -printf '%P\n'
find . -maxdepth 1 -type f -printf '%P\n'
) | \
while read l ; do
	if has ${l} ${libs} ; then
		if [ -L "${l}" ] ; then
			vecho "delinking $l"
			cp "$l" "../.$l"
			rm "$l"
			mv "../.$l" "$l"
		else
			vecho "keeping $l"
		fi
	else
		vecho "trimming $l"
		rm "${l}"
	fi
done
