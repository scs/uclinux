#
#  Copyright (c) International Business Machines  Corp., 2001
#
#  This program is free software;  you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY;  without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See
#  the GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program;  if not, write to the Free Software
#  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
#

###########################################################################
# name of file	: Makefile						  #
# description	: make(1) description file for the send(2) tests.	  #
###########################################################################
CFLAGS+=	-I../../../../include -Wall
LOADLIBES+=	-L../../../../lib -lc    

SRCS=$(wildcard *.c)
TARGETS=$(patsubst %.c,%,$(SRCS))
INPUTFILES=$(wildcard *.input)

all: $(TARGETS)

romfs:
	@set -e; for i in $(TARGETS); do $(ROMFSINST) /bin/$$i ; done
	$(ROMFSINST) ./fs_test.sh /bin/fs_test.sh
	$(ROMFSINST) ./fs_inod/err_log /bin/err_log
	$(ROMFSINST) ./fs_inod/fs_error_log /bin/fs_error_log
	$(ROMFSINST) ./fs_inod/fs_inod_bf /bin/fs_inod_bf
	$(ROMFSINST) ./fs_inod/make_subdirs /bin/make_subdirs
	$(ROMFSINST) ./fs_inod/rm_files /bin/rm_files
	$(ROMFSINST) ./fs_inod/touch_files /bin/touch_files

clean:
	rm -f $(TARGETS)
	rm -rf *.gdb
