#!/bin/sh
#
# Run this script with a three arguments:
#
#    1.   The name of the sqlite.h.in source file
#    2.   The VERSION file containing the current version number
#    3.   The name of the awk executable
#
# The output is the text of the sqlite3.h file with version
# information inserted.
#
src="$1"
vfile="$2"
awk="$3"
VERSION=`cat $vfile`
VNUMBER=`echo $VERSION | sed 's/[^0-9]/ /g' \
           | $awk '{printf "%d%03d%03d",$1,$2,$3}'`
echo VERSION=$VERSION
echo VNUMBER=$VNUMBER
