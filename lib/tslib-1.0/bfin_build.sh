#!/bin/sh -x

./configure --host=bfin-uclinux --disable-h2200-linear --disable-ucb1x00 --disable-corgi --disable-collie --disable-h3600 --disable-mk712 --disable-arctic2 CFLAGS='-mfdpic -DUSE_INPUT_API'

make 
