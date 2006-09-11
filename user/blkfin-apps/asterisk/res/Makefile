#
# Asterisk -- A telephony toolkit for Linux.
# 
# Makefile for CDR backends (dynamically loaded)
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
MODS = $(patsubst %.so, %.la, $(RES_SO))

#MODS+=$(shell if [ -f "/usr/include/odbcinst.h" ]; then echo "res_odbc.so res_config_odbc.so"; fi)
#MODS+=$(shell if [ -f "/usr/local/include/odbcinst.h" ]; then echo "res_odbc.so res_config_odbc.so"; fi)
#MODS+=$(shell if [ -f "/usr/include/osp/osp.h" ]; then echo "res_osp.so"; fi)

CRYPTO_LIBS=-lssl -lcrypto

#CFLAGS+=
#CFLAGS+=$(shell [ -f /usr/include/linux/zaptel.h ] && echo " -DZAPATA_MOH")
#CFLAGS+=$(shell [ -f /usr/local/include/zaptel.h ] && echo " -DZAPATA_MOH")
#
# Work around buggy RedHat 9.0
#
CFLAGS+=-DOPENSSL_NO_KRB5
OSPLIB=/usr/lib/libosp.a

all: depend $(MODS)

install: all
	rm -f $(DESTDIR)$(ASTHEADERDIR)/parking.h
	rm -f $(DESTDIR)$(MODULES_DIR)/app_agi.so 
	rm -f $(DESTDIR)$(MODULES_DIR)/res_parking.so
	for x in $(RES_SO); do touch $(DESTDIR)$(MODULES_DIR)/$$x ; done

#res_crypto.so: res_crypto.o
#	$(CC) $(SOLINK) -o $@ $< $(CRYPTO_LIBS)

clean:
	rm -f *.la *.lo *.o .depend

#res_odbc.so: res_odbc.o
#	$(CC) $(SOLINK) -o $@ $< -lodbc

#res_osp.so: res_osp.o $(OSPLIB)
#	$(CC) $(SOLINK) -o $@ $< $(OSPLIB)

#%.so : %.o
#	$(CC) $(SOLINK) -o $@ $<

ifneq ($(wildcard .depend),)
include .depend
endif

depend: .depend

.depend:
	../mkdep $(CFLAGS) `ls *.c`

env:
	env
