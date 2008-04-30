#!/bin/sh

cwd=$PWD/../ltp
LTP_TESTCASES_DIR=$cwd/ltp-full-20071031/testcases/bin

rm -fr testcase
mkdir -p testcase

cp $LTP_TESTCASES_DIR/mmap1 testcase
if [ $? != 0 ] ; then
    echo "copy mmap1 failed"
    exit
fi

cp $LTP_TESTCASES_DIR/mmap0[2-9] testcase
if [ $? != 0 ] ; then
    echo "copy mmap0[2-9] failed"
    exit
fi

rcp testcase/mmap* root@10.100.4.50:/bin
if [ $? != 0 ] ; then
    echo "rcp failed"
    exit
fi

echo "rcp pass"
