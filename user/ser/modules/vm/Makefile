# $Id: Makefile,v 1.3 2003/05/23 15:43:44 andrei Exp $
#
# print example module makefile
#
# 
# WARNING: do not run this directly, it should be run by the master Makefile

include ../../Makefile.defs
auto_gen=
NAME=vm.so
LIBS=

ifeq ($(MAKELEVEL), 0)
# make called directly in the module dir!

all::
	cd ../..; make all

else

include ../../Makefile.modules

endif
