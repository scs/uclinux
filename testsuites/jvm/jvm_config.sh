#!/bin/sh

if [ $# -ne 2 ]; then
	echo "Usage: $0 path"
	echo "Please append path where jikes and kaffe source code located in"
fi

src_path=$1
cur_path=`pwd`

#
# Build jikes on host machine
#
if [ ! -e "$1/jikes" ]
then
	echo "Error: Directory $1/jikes does not exist"
	exit 1
fi

cd $1/jikes
rm -rf /opt/jikes
./configure --prefix=/opt/jikes
if [ $? -ne 0 ]
then
	echo "Error: Jikes configuration failed"
	exit 1
fi

make
if [ $? -ne 0 ]
then
	echo "Error: Jikes make failed"
	exit 1
fi

make install
if [ $? -ne 0 ]
then
	echo "Error: Jikes make install failed"
	exit 1
fi

export PATH=$PATH:/opt/jikes/bin

#
# Build kaffe on host machine
#
if [ ! -e "$1/kaffe" ]
then
	echo "Error: Directory $1/kaffe does not exist"
	exit 1
fi

cd $1/kaffe
rm -rf /opt/kaffe
./configure --prefix=/opt/kaffe
if [ $? -ne 0 ]
then
	echo "Error: Kaffe configuration failed"
	exit 1
fi

make
if [ $? -ne 0 ]
then
	echo "Error: Kaffe make failed"
	exit 1
fi

make install
if [ $? -ne 0 ]
then
	echo "Error: Kaffe make install failed"
	exit 1
fi

export PATH=$PATH:/opt/kaffe/bin


#
# Check out kaffe code from local CVS for JVM run on uClinux
#
cd $cur_path
rm -rf blkbfin-apps
cvs -d :pserver:anonymous@10.99.29.20:/cvsroot/uclinux533 co -A -P blkbfin-apps/kaffe
if [ $? -ne 0 ]
then
	echo "Error: Check out from CVS failed."
	exit 1
fi
cp $cur_path/build_kaffe_uclinux.sh $cur_path/blkbfin-apps/kaffe
cd $cur_path/blkbfin-apps/kaffe
./build_kaffe_uclinux.sh
if [ $? -ne 0 ]
then
	echo "Error: Kaffe build failed"
	exit 1
fi
#make
#if [ $? -ne 0 ]
#then
#	echo "Error: Kaffe make failed"
#	exit 1
#fi

# Increase the stack size
#bfin-uclinux-flthdr -s 1048576 -o kaffe.flt kaffe/kaffe/kaffe-bin
#if [ $? -ne 0 ]
#then
#	echo "Error: Change stack size failed"
#	exit 1
#fi

#
# Compile HelloWorldApp.java
#
cd $cur_path
javac HelloWorldApp.java
if [ ! -e "HelloWorldApp.class" ]
then
	echo "Error: File HelloWorldApp.class not exist"
	exit 1
fi

echo "*** Configuration for JVM test is done ***"

exit 0
