# Makefile for uClibc
#
# Copyright (C) 2002-2003 Erik Andersen <andersen@uclibc.org>
#
# This program is free software; you can redistribute it and/or modify it under
# the terms of the GNU Library General Public License as published by the Free
# Software Foundation; either version 2 of the License, or (at your option) any
# later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. See the GNU Library General Public License for more
# details.
#
# You should have received a copy of the GNU Library General Public License
# along with this program; if not, write to the Free Software Foundation, Inc.,
# 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA

TOPDIR=../../../
include $(TOPDIR)Rules.mak

LIBMP4FF=libmp4ff.a
LIBMP4FF_SHARED=libmp4ff.so
LIBMP4FF_SHARED_FULLNAME=libmp4ff-$(MAJOR_VERSION).$(MINOR_VERSION).$(SUBLEVEL).so


#Taken from Makefile.old
srcdir = .
top_srcdir = ../..
top_builddir = ../..
include_HEADERS = mp4ff.h

libmp4ff_la_SOURCES = mp4ff.c mp4atom.c mp4meta.c mp4sample.c mp4util.c  mp4tagupdate.c drms.c


AM_CFLAGS = -O2 -g -DUSE_TAGGING=1
DEFS = -DHAVE_CONFIG_H
DEFAULT_INCLUDES =  -I. -I$(srcdir) -I$(top_builddir)
CFLAGS +=  -O2 $(AM_CFLAGS)

CSRC = $(libmp4ff_la_SOURCES)
OBJS=$(patsubst %.c,%.o, $(CSRC))

#***


all: $(OBJS) $(LIBMP4FF)

$(LIBMP4FF): ar-target

ar-target: $(OBJS)
	$(AR) $(ARFLAGS) $(LIBMP4FF) $(OBJS)
	$(INSTALL) -d $(TOPDIR)lib
	$(RM) $(TOPDIR)lib/$(LIBMP4FF)
	$(INSTALL) -m 644 $(LIBMP4FF) $(TOPDIR)lib


$(OBJS): %.o : %.c
	$(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(CFLAGS) -c $< -o $@
	$(STRIPTOOL) -x -R .note -R .comment $*.o

$(OBJ): Makefile

shared: all
	$(LD) $(LDFLAGS) -soname=$(LIBMP4FF_SHARED).$(MAJOR_VERSION) \
		-o $(LIBMP4FF_SHARED_FULLNAME) --whole-archive $(LIBMP4FF) \
		--no-whole-archive $(TOPDIR)libc/misc/internals/interp.o \
		-L$(TOPDIR)lib -lc $(LDADD_LIBFLOAT) $(LIBGCC);
	$(INSTALL) -d $(TOPDIR)lib
	$(RM) $(TOPDIR)lib/$(LIBMP4FF_SHARED_FULLNAME) $(TOPDIR)lib/$(LIBMP4FF_SHARED).$(MAJOR_VERSION)
	$(INSTALL) -m 644 $(LIBMP4FF_SHARED_FULLNAME) $(TOPDIR)lib
	$(LN) -sf $(LIBMP4FF_SHARED_FULLNAME) $(TOPDIR)lib/$(LIBMP4FF_SHARED)
	$(LN) -sf $(LIBMP4FF_SHARED_FULLNAME) $(TOPDIR)lib/$(LIBMP4FF_SHARED).$(MAJOR_VERSION)


clean: 
	$(RM) *.[oa] *~ core $(LIBMP4FF_SHARED)* $(LIBMP4FF_SHARED_FULLNAME)*
