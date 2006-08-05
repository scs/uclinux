#!/bin/sh

# Update the /testing/pluto/log.ref files from those just created in 
# /tmp/log by the "pluto_unit_tests.sh" script. 
#
# run this script in a UML after running pluto_unit_tests.sh
#
# $Id$
#
#

mount -o rw,remount /testing
cd /tmp/log
for i in */w?-log
do
	cp $i /tmp/log.ref/$i
done


# $Log$
# Revision 1.1  2006/08/05 02:12:08  vapier
# merge from upstream uClinux
#
# Revision 1.1  2003/05/21 15:45:57  mcr
# 	update the log.ref files from the newly generated files in
# 	/tmp/log. Run this in a UML.
#
#
#
