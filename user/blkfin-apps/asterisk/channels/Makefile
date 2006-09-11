#
# Asterisk -- A telephony toolkit for Linux.
# 
# Makefile for Channel backends (dynamically loaded)
#
# Copyright (C) 1999, Mark Spencer
#
# Mark Spencer <markster@linux-support.net>
#
# Edited By Belgarath <> Aug 28 2004
# Added bare bones ultrasparc-linux support.
#
# This program is free software, distributed under the terms of
# the GNU General Public License
#
# DR 18/9/05: Modified for static modules under uClinux using GNU libtool dynamic lib
# emulation

CHANNELS_LA = $(patsubst %.so, %.la, $(CHANNELS_SO))

include ../Makefile.include

call: depend $(CHANNELS_LA) 

all: $(CHANNEL_LA)

clean:
	rm -f *.la *.lo *.o .depend
	rm -f busy.h ringtone.h gentone gentone-ulaw

ifneq ($(wildcard .depend),)
include .depend
endif

gentone: gentone.c
	$(CC) -o gentone gentone.c -lm

gentone-ulaw: gentone-ulaw.c
	$(CC) -o gentone-ulaw gentone-ulaw.c -lm

busy.h: gentone
	./gentone busy 480 620

ringtone.h: gentone
	./gentone ringtone 440 480

chan_iax2.la: chan_iax2.lo iax2_parser.lo iax2_provision.lo
	$(LIBTOOL) --tag=CC --mode=link $(CC) -o $@ chan_iax2.lo \
	iax2_parser.lo iax2_provision.lo -rpath /usr/local/lib -module -static

install: all
	for x in $(CHANNELS_SO); do touch $(DESTDIR)$(MODULES_DIR)/$$x ; done

depend: .depend

.depend:
	../mkdep $(CFLAGS) `ls *.c`

env:
	env

