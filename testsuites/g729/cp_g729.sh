#!/bin/bash

USER=/home/test/work/cruise
UCLINUX_DIST_PATH=$USER/checkouts/uclinux-dist
G729_PATH=$UCLINUX_DIST_PATH/testsuites/g729

cd $G729_PATH
mkdir -p g729
mkdir -p g729/test_data
mkdir -p g729/test_data/g729a
mkdir -p g729/test_data/g729a/std_in_de
mkdir -p g729/test_data/g729a/std_in_en
mkdir -p g729/test_data/g729a/std_out_de
mkdir -p g729/test_data/g729a/std_out_en
mkdir -p g729/test_data/g729ab

cd $UCLINUX_DIST_PATH/lib/libbfgdots/g729/test
cp -f alltests.sh g729ab_test g729ab_testsimgot g729ab_testfdpic g729ab_testfdpic_so ../src.fdpic/libg729ab.so $G729_PATH/g729/
cp -f test_data/g729a/std_in_de/*  $G729_PATH/g729/test_data/g729a/std_in_de/
cp -f test_data/g729a/std_in_en/*  $G729_PATH/g729/test_data/g729a/std_in_en/
cp -f test_data/g729a/std_out_de/* $G729_PATH/g729/test_data/g729a/std_out_de/
cp -f test_data/g729a/std_out_en/* $G729_PATH/g729/test_data/g729a/std_out_en/
