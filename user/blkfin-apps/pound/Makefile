# Pound - the reverse-proxy load-balancer
# Copyright (C) 2002 Apsis GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330,
# Boston, MA  02111-1307, USA.
#
# Contact information:
# Apsis GmbH
# P.O.Box
# 8707 Uetikon am See
# Switzerland
# Tel: +41-1-920 4904
# EMail: roseg@apsis.ch
#
# $Id$
CC=bfin-uclinux-gcc
CFLAGS=-DF_CONF=\"$(F_CONF)\" -DVERSION=\"`cat VERSION`\" -g -O2  -DNEED_STACK -DHAVE_SYSLOG_H=1 -I$(ROOTDIR)/lib/libssl/include  -D_REENTRANT -D_THREAD_SAFE

LIBS=-L$(ROOTDIR)/lib -lssl -lcrypto  -lpthread

prefix=$(ROMFSDIR)/usr/local
exec_prefix=${prefix}

# Configuration file default; if none, look at config.c for default!
F_CONF=/usr/local/etc/pound.cfg

OBJS=pound.o http.o config.o svc.o

all:	pound pound.8

pound:	$(OBJS)
		bfin-uclinux-gcc -Wl,-elf2flt  -o pound $(OBJS) $(LIBS)

$(OBJS):	pound.h

install:	all
		[ -d ${exec_prefix}/sbin ] || mkdir ${exec_prefix}/sbin
		/usr/bin/install -c -o bin -g bin -m 555 -s pound ${exec_prefix}/sbin/pound
		[ -d ${prefix}/man ] || mkdir ${prefix}/man
		[ -d ${prefix}/man/man8 ] || mkdir ${prefix}/man/man8
		/usr/bin/install -c -o bin -g bin -m 644 pound.8 ${prefix}/man/man8/pound.8

romfs:
		$(ROMFSINST) /bin/pound
		test -d $(ROMFSDIR)/etc/pound || mkdir $(ROMFSDIR)/etc/pound
		cp ./mycert.pem $(ROMFSDIR)/etc/pound
		test -d $(ROMFSDIR)/usr/local \
		|| (mkdir $(ROMFSDIR)/usr/local && mkdir $(ROMFSDIR)/usr/local/etc)
		cp ./pound.cfg $(ROMFSDIR)/usr/local/etc
		cp ./index.html $(ROMFSDIR)/home/httpd

clean:
		rm -f pound $(OBJS)

uninstall:
		-rm -f ${exec_prefix}/sbin/pound ${prefix}/man/man8/pound.8 ${prefix}/man/cat8/pound.8
