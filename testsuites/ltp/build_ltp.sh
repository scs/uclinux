#!/bin/sh

if [ $# -ne 1 ]; then
       echo "Usage: $0 cvs_server_addr"
       echo "Please append SVN repository ip address"
       exit 1
fi       
cvs_server_addr=$1

LTP_SUB_DIR=ltp-full-20071031
if [ -d $LTP_SUB_DIR ]
then
	rm -rf $LTP_SUB_DIR
	echo "$0:	Clean directory"
fi

## Ignore this step by svn ##
# Checkout current file
#echo "$0:	Checking out from CVS, file [current]"
#cvs -Q -d :pserver:anonymous@$cvs_server_addr:/cvsroot/uclinux533 co -A -P ltp/current
#if [ $? -ne 0 ]
#then
#	echo "$0:	Error, CVS checkout failed"
#	exit 1
#fi

## We don't need patch for Makefile now ##
# Checkout patch file for Makefiles 
#echo "$0:	Checking out from CVS, file [Makefile.patch]"
#cvs -Q -d :pserver:anonymous@$cvs_server_addr:/cvsroot/uclinux533 co -A -P ltp/Makefile.patch
#if [ $? -ne 0 ]
#then
#	echo "$0:	Error, CVS checkout failed"
#	exit 1
#fi

# Checkout ltp source directory
#LTP_WORKING_DIR=`cat ltp/current`
#LTP_SUB_DIR=ltp-full-20071031
CWD=`pwd`

#echo "$0:	Get ltp working directory [$LTP_WORKING_DIR]"

echo "$0:	Checking out from SVN, ltp/$LTP_SUB_DIR"
#cvs -Q -d :pserver:anonymous@$cvs_server_addr:/cvsroot/uclinux533 co -A -P $LTP_SUB_DIR
svn -q co svn://$cvs_server_addr/ltp/trunk/$LTP_SUB_DIR
if [ $? -ne 0 ]
then
	echo "$0:	Error, SVN checkout failed"
	exit 1
fi

# Go to working directory
echo "$0:	Go to working directory"
cd $LTP_SUB_DIR

## We don't need patch for Makefile now ##
# Patch for Makefiles
#echo "$0:	Patching Makefiles"
#patch -p0 < ../Makefile.patch
#if [ $? -ne 0 ]
#then
#	echo "$0:	Error, patching Makefiles failed"
#	exit 1
#fi

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
