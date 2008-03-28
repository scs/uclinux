#!/bin/sh 

./configure	--host=bfin-linux-uclibc --build=x86_64-unknown-linux-gnu \
		--x-includes=`pwd`/../nxlib-0.45/X11/include \
		--x-libraries=`pwd`/../nxlib-0.45
