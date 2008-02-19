#!/bin/sh

AM_VERSION=1.9
#1.9 is the recommended version currently
if test -n "$AM_VERSION" ; then
	ACLOCAL=aclocal-${AM_VERSION}
	AUTOMAKE=automake-${AM_VERSION}
else
	ACLOCAL=aclocal
	AUTOMAKE=automake
fi

echo "Generating build scripts in mediastreamer..."
set -x
libtoolize --copy --force
autoheader
$ACLOCAL 
$AUTOMAKE --force-missing --add-missing --copy
autoconf
