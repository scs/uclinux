#!/bin/sh

cvs_server_addr=10.99.22.20
LTP_SUB_DIR=ltp/ltp-full-20060411

cvs -d :pserver:anonymous@$cvs_server_addr:/cvsroot/uclinux533 co -A -P $LTP_SUB_DIR

cd $LTP_SUB_DIR
make uclinux
make uclinux_install
