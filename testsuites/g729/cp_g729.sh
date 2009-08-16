#!/bin/bash

USER=/home/test/work/cruise
UCLINUX_DIST_PATH=$USER/checkouts/uclinux-dist
G729_PATH=$UCLINUX_DIST_PATH/testsuites/g729

cd $G729_PATH
mkdir -p g729/test_data/

cd $UCLINUX_DIST_PATH/lib/libbfgdots/g729/test
cp -f alltests.sh g729ab_test g729ab_testsimgot g729ab_testfdpic g729ab_testfdpic_so ../src.fdpic/libg729ab.so $G729_PATH/g729/
cp -rf test_data/  $G729_PATH/g729/
