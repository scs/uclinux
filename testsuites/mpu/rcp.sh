#!/bin/sh

echo "$0:       Start rcp.sh at `date`"

mpu_dir=$PWD
ltp_ver=ltp-full-20081130
ltp_src_dir=$mpu_dir/$ltp_ver
ltp_testcases_dir=$ltp_src_dir/testcases/bin
cvs_server_addr=10.99.22.20


#Check out ltp source from svn server
if [ -d $ltp_src_dir ]
then
    rm -fr $ltp_src_dir
fi
echo "$0:       Checking out $ltp_ver from SVN"
svn -q co svn://$cvs_server_addr/ltp/trunk/$ltp_ver
if [ $? -ne 0 ]
then
    echo "$0:       Error, SVN checkout failed"
    exit 1
fi


#Apply patch of mpu related test cases in ltp source dir
echo "$0:       Apply patch to ltp source"
patch -d $ltp_src_dir -p0 < ltp_Makefile.patch
if [ $? -ne 0 ]
then
    echo "$0:       Error, apply ltp patch failed"
    exit 1
fi


#Build ltp testsuites and install
echo "$0:       Build ltp source"
make -C $ltp_src_dir -s uclinux > /dev/null 2>&1
if [ $? -ne 0 ]
then
    echo "$0:       Error, make failed" 
    exit 1
fi

echo "$0:       Install ltp test cases"
make -C $ltp_src_dir -s uclinux_install > /dev/null 2>&1
if [ $? -ne 0 ]
then
    echo "$0:       Error, make install failed" 
    exit 1
fi
echo "$0:       LTP build done"


#Copy test cases to mpu local folder
echo "$0:       Copy mpu test cases to board"
rm -fr testcase
mkdir -p testcase

cp $ltp_testcases_dir/mmap1 $ltp_testcases_dir/mmap0[2-8] testcase
if [ $? != 0 ] ; then
    echo "copy mpu test cases failed"
    exit 1
fi

rcp testcase/mmap* root@10.100.4.50:/bin
if [ $? != 0 ] ; then
    echo "rcp failed"
    exit 1
fi

echo "$0:       Finish rcp.sh at `date`"
echo "rcp pass"
exit 0
