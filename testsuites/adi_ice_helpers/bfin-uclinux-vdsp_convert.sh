#!/bin/sh -x

if [ -r $1 ] ; then
    echo Converting 
    (grep ^PC $1 | awk -F [ '{print $1 " "  $2" " $3}' | awk -F ]  '{print $1 " " $2 }' | sort -k 2 -g | awk '{printf "PC[%s]\t%s\n", $2, $3}') > $1.prof
else
    echo Can not find $1 to convert
fi
