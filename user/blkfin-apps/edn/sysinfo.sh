#!/bin/sh

# the arguments of this script are the compiler name and flags

# try to solve a chicken-and-egg problem on SunOS
# ucb's test program does not handle -L like the other test programs
# let's try to find another implementation
if test -x /bin/test; then
    TEST=/bin/test;
else
    if test -x /usr/bin/test; then
        TEST=/usr/bin/test;
    else
        # cross your fingers that it's not like ucb test
        TEST=test;
    fi
fi

if (`$1 -v >/dev/null 2>&1`) ; then
    gccversion="$1 : `$1 -v < /dev/null 2>&1 | grep -i " version "`"
else
    gccversion="$1"
fi

libcversion=""
shift
while [ $# -ge 1 ]; do
    libcversion="$libcversion $1"
    shift
done

rm -f sysinfo.crm sysinfoc.c hello

# this bombs out on Ultrix which expect "cut -d"

compsystem=`uname -a | cut -b 1-78`
compdate=`date|cut -b1-55`

# let's hope that ctrl-c is not part of any string here
# this also will barf later if " is in any of the strings

sed -e "s%CCVERSION%$gccversion" -e "s%LIBCVERSION%$libcversion"\
    -e "s%SYSTEM%$compsystem" -e "s%DATE%$compdate"\
    sysinfo.c.template > sysinfo.c

