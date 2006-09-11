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
# Modified by David Rowe 2005 for static linking

USE_MYSQL_VM_INTERFACE=0
USE_POSTGRES_VM_INTERFACE=0

include ../Makefile.include
APPS = $(patsubst %.so, %.la, $(APPS_SO))

ifneq (${OSARCH},Darwin)
APPS+=app_intercom.la
endif

#APPS+=app_sql_postgres.so
#APPS+=app_sql_odbc.so
#APPS+=app_rpt.so

#APPS+=$(shell if [ -f /usr/include/linux/zaptel.h ]; then echo "app_zapras.so app_meetme.so app_flash.so app_zapbarge.so app_zapscan.so" ; fi)
#APPS+=$(shell if [ -f /usr/local/include/zaptel.h ]; then echo "app_zapras.so app_meetme.so app_flash.so app_zapbarge.so app_zapscan.so" ; fi)
#APPS+=$(shell if [ -f /usr/include/osp/osp.h ]; then echo "app_osplookup.so" ; fi)

ifeq ($(USE_POSTGRES_VM_INTERFACE),1)
CFLAGS+=-DUSEPOSTGRESVM
endif

ifeq ($(USE_MYSQL_VM_INTERFACE),1)
CFLAGS+=-DUSEMYSQLVM
endif

all: $(APPS)

clean:
	rm -f *.la *.lo *.o look .depend

#app_rpt.so : app_rpt.o
#	$(CC) $(SOLINK) -o $@ $< -ltonezone

install: all
	for x in $(APPS_SO); do touch $(DESTDIR)$(MODULES_DIR)/$$x ; done
	rm -f $(DESTDIR)$(MODULES_DIR)/app_datetime.so

#app_voicemail.so : app_voicemail.o
#ifeq ($(USE_MYSQL_VM_INTERFACE),1)
#	$(CC) $(SOLINK) -o $@ $(MLFLAGS) $< -L/usr/lib/mysql -lmysqlclient -lz
#else
#ifeq ($(USE_POSTGRES_VM_INTERFACE),1)
#	$(CC) $(SOLINK) -o $@ $(MLFLAGS) $< -lpq
#else
#	$(CC) $(SOLINK) -o $@ $(MLFLAGS) $< 
#endif
#endif

#app_sql_postgres.o: app_sql_postgres.c
#	$(CC) -pipe -I/usr/local/pgsql/include $(CFLAGS) -c -o app_sql_postgres.o app_sql_postgres.c

#app_sql_postgres.so: app_sql_postgres.o
#	$(CC) $(SOLINK) -o $@ $< -L/usr/local/pgsql/lib -lpq

#app_sql_odbc.so: app_sql_odbc.o
#	$(CC) $(SOLINK) -o $@ $< -lodbc

#look:	look.c
#	$(CC) -pipe -O6 -g look.c -o look -lncurses

ifneq ($(wildcard .depend),)
include .depend
endif

depend: .depend

.depend:
	../mkdep $(CFLAGS) `ls *.c`

env:
	env
