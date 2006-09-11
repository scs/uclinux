#
# Asterisk -- A telephony toolkit for Linux.
# 
# Makefile for file format modules
#
# Copyright (C) 1999, Mark Spencer
#
# Mark Spencer <markster@linux-support.net>
#
# This program is free software, distributed under the terms of
# the GNU General Public License
#
# Modified by David Rowe Sep 2005 for static modules

include ../Makefile.include
FORMAT_LIBS = $(patsubst %.so, %.la, $(FORMATS_SO))

#FORMAT_LIBS+=format_jpeg.so
#
# G723 simple frame is depricated
#
#FORMAT_LIBS+=format_g723.so

GSMLIB=../codecs/gsm/lib/libgsm.a

#CFLAGS+=-fPIC

all: depend $(FORMAT_LIBS)

clean:
	rm -f *.so *.o *.la *.lo .depend

#%.so : %.o
#	$(CC) $(SOLINK) -o $@ $<

ifneq ($(wildcard .depend),)
include .depend
endif

#format_mp3.so : format_mp3.o
#	$(CC) $(SOLINK) -o $@ $< -lm

install: all
	for x in $(FORMATS_SO); do touch $(DESTDIR)$(MODULES_DIR)/$$x ; done

depend: .depend

.depend:
	../mkdep $(CFLAGS) `ls *.c`
