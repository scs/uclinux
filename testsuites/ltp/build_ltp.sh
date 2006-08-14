#!/bin/sh

if [ $# -ne 1 ]; then
       echo "Usage: $0 cvs_server_addr"
       echo "Please append CVS repository ip address"
       exit 1
fi       
cvs_server_addr=$1

if [ -d ltp ]
then
	rm -rf ltp
	echo "$0:	Clean directory"
fi

# Checkout current file
echo "$0:	Checking out from CVS, file [current]"
cvs -Q -d :pserver:anonymous@$cvs_server_addr:/cvsroot/uclinux533 co -A -P ltp/current
if [ $? -ne 0 ]
then
	echo "$0:	Error, CVS checkout failed"
	exit 1
fi

# Checkout patch file for Makefiles 
echo "$0:	Checking out from CVS, file [Makefile.patch]"
cvs -Q -d :pserver:anonymous@$cvs_server_addr:/cvsroot/uclinux533 co -A -P ltp/Makefile.patch
if [ $? -ne 0 ]
then
	echo "$0:	Error, CVS checkout failed"
	exit 1
fi

# Checkout ltp source directory
LTP_WORKING_DIR=`cat ltp/current`
LTP_SUB_DIR=ltp/$LTP_WORKING_DIR
CWD=`pwd`

echo "$0:	Get ltp working directory [$LTP_WORKING_DIR]"

echo "$0:	Checking out from CVS, ltp/$LTP_WORKING_DIR"
cvs -Q -d :pserver:anonymous@$cvs_server_addr:/cvsroot/uclinux533 co -A -P $LTP_SUB_DIR
if [ $? -ne 0 ]
then
	echo "$0:	Error, CVS checkout failed"
	exit 1
fi

# Go to working directory
echo "$0:	Go to working directory"
cd $LTP_SUB_DIR

# Patch for Makefiles
echo "$0:	Patching Makefiles"
patch -p0 < ../Makefile.patch
if [ $? -ne 0 ]
then
	echo "$0:	Error, patching Makefiles failed"
	exit 1
fi

# Build ltp testsuites
echo "$0:	Make ..."
make -s uclinux > /dev/null 2>&1
if [ $? -ne 0 ]
then
	echo "$0:	Error, make failed" 
	exit 1
fi

echo "$0:	make install ..."
make -s uclinux_install > /dev/null 2>&1
if [ $? -ne 0 ]
then
	echo "$0:	Error, make install failed" 
	exit 1
fi
echo "$0:	LTP build done"

cd $CWD
exit 0
