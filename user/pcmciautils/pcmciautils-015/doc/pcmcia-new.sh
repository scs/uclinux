#!/bin/sh
#
# this is an examle of the /etc/init.d/pcmcia-new init script as described in
# cardmgr-to-pcmciautils.txt
#

#
# set this to the driver to use, one of:
# yenta_socket, i82365, i82092, pd6729, tcic, etc.
#
DRIVER=yenta_socket
DRIVER_OPTS=

# in case modprobe and rmmod are not in PATH: set MODUTILS_PATH to the right
# path an uncomment the following two lines:
#MODUTILS_PATH=
#export PATH=$MODUTILS_PATH:$PATH

case "$1" in
	start)
		modprobe $DRIVER $DRIVER_OPTS > /dev/null 2>&1
		modprobe pcmcia > /dev/null 2>&1 # just in case it's not auto-loaded
		;;

	stop)
		pccardctl eject
		MODULES=`lsmod | grep "pcmcia " | awk '{print $4}' | tr , ' '`
		for i in $MODULES ; do
			rmmod $i > /dev/null 2>&1
		done
		rmmod pcmcia > /dev/null 2>&1
		rmmod $DRIVER > /dev/null 2>&1
		rmmod rsrc_nonstatic > /dev/null 2>&1
		rmmod pcmcia_core > /dev/null 2>&1
		;;
esac
