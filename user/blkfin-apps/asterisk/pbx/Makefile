#
# Asterisk -- A telephony toolkit for Linux.
# 
# Makefile for PBX frontends (dynamically loaded)
#
# Copyright (C) 1999, Mark Spencer
#
# Mark Spencer <markster@linux-support.net>
#
# This program is free software, distributed under the terms of
# the GNU General Public License
#

include ../Makefile.include
PBX_LIB = $(patsubst %.so, %.la, $(PBX_SO))

all: depend $(PBX_LIB)

clean:
	rm -f *.la *.lo *.o .depend


ifneq ($(wildcard .depend),)
include .depend
endif

install: all
	for x in $(PBX_SO); do touch $(DESTDIR)$(MODULES_DIR)/$$x ; done

depend: .depend

.depend:
	../mkdep $(CFLAGS) `ls *.c`
