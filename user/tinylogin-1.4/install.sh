#!/bin/sh

if [ `id -u` -ne 0 ]; then
    echo " ";
    echo "Aborting install -- You must be root, otherwise I can't.";
    echo "make tinylogin be setuid root, which will cause it to fail.";
    echo " ";
    exit 1;
fi;

prefix=$1
if [ "$prefix" = "" ]; then
    echo "No installation directory, aborting."
    exit 1;
fi
if [ "$2" = "--hardlinks" ]; then
    linkopts="-f"
else
    linkopts="-fs"
fi
h=`sort tinylogin.links | uniq`


mkdir -p $prefix/bin || exit 1

for i in $h ; do
	appdir=`dirname $i`
	mkdir -p $prefix/$appdir || exit 1
	if [ "$2" = "--hardlinks" ]; then
	    bb_path="$prefix/bin/tinylogin"
	else
	    case "$appdir" in
		/)
		    bb_path="bin/tinylogin"
		;;
		/bin)
		    bb_path="tinylogin"
		;;
		/sbin)
		    bb_path="../bin/tinylogin"
		;;
		/usr/bin|/usr/sbin)
		    bb_path="../../bin/tinylogin"
		;;
		*)
		echo "Unknown installation directory: $appdir"
		exit 1
		;;
	    esac
	fi
	echo "  $prefix$i -> $bb_path"
	ln $linkopts $bb_path $prefix$i || exit 1
done
rm -f $prefix/bin/tinylogin || exit 1
install -m 4755 --owner=root --group=root ./tinylogin $prefix/bin/tinylogin || exit 1

exit 0
