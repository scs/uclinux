# Generated automatically from Makefile.in by configure.
# Makefile for extras.
#
# Copyright (C)1995,1998 by Jef Poskanzer <jef@acme.com>. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.

prefix =	/usr/local
exec_prefix =	${prefix}
BINDIR =	${exec_prefix}/sbin
WEBDIR =	$(prefix)/www
CGIBINDIR =	$(WEBDIR)/cgi-bin
MANDIR =	${prefix}/man

CC =		gcc
CCOPT =		-O2
DEFS =		 -DHAVE__PROGNAME=1 -DHAVE_FCNTL_H=1 -DHAVE_MEMORY_H=1 -DHAVE_PATHS_H=1 -DTIME_WITH_SYS_TIME=1 -DHAVE_DIRENT_H=1 -DHAVE_LIBCRYPT=1 -DHAVE_STRERROR=1 -DHAVE_WAITPID=1 -DHAVE_SNPRINTF=1 -DHAVE_UNISTD_H=1 -DHAVE_GETPAGESIZE=1 -DHAVE_MMAP=1 
INCLS =		-I..
CFLAGS =	$(CCOPT) $(DEFS) $(INCLS)
STATICFLAG =	-static
LDFLAGS =	
LIBS =		-lcrypt 
NETLIBS =	
INSTALL =	/usr/bin/install -c

CLEANFILES =	*.o makeweb htpasswd



.c.o:
	@rm -f $@
	$(CC) $(CFLAGS) -c $*.c

all:		makeweb htpasswd

makeweb:	makeweb.o
	$(CC) $(LDFLAGS) makeweb.o -o makeweb $(LIBS) $(NETLIBS)

makeweb.o:	makeweb.c ../config.h
	$(CC) $(CFLAGS) -DWEBDIR=\"$(WEBDIR)\" -c makeweb.c

htpasswd:	htpasswd.o
	$(CC) $(LDFLAGS) $(STATICFLAG) htpasswd.o -o htpasswd $(LIBS)

htpasswd.o:	htpasswd.c ../config.h
	$(CC) $(CFLAGS) -DWEBDIR=\"$(WEBDIR)\" -c htpasswd.c


install:	all
	rm -f $(BINDIR)/makeweb $(BINDIR)/htpasswd $(BINDIR)/syslogtocern
	cp makeweb $(BINDIR)/makeweb
	chgrp $(WEBGROUP) $(BINDIR)/makeweb
	chmod 2755 $(BINDIR)/makeweb
	cp htpasswd $(BINDIR)/htpasswd
	cp syslogtocern $(BINDIR)/syslogtocern
	rm -f $(MANDIR)/man1/makeweb.1
	cp makeweb.1 $(MANDIR)/man1/makeweb.1
	rm -f $(MANDIR)/man1/htpasswd.1
	cp htpasswd.1 $(MANDIR)/man1/htpasswd.1
	rm -f $(MANDIR)/man8/syslogtocern.8
	cp syslogtocern.8 $(MANDIR)/man8/syslogtocern.8

clean:
	rm -f $(CLEANFILES)

distclean:
	rm -f $(CLEANFILES) Makefile
