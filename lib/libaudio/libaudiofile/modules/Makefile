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

LIBMODULES=libmodules.a
LIBMODULES_SHARED=libmodules.so
LIBMODULES_SHARED_FULLNAME=libmodules-$(MAJOR_VERSION).$(MINOR_VERSION).$(SUBLEVEL).so


CSRC =   g711.c pcm.c msadpcm.c ima.c adpcm.c rebuffer.c 
OBJS=$(patsubst %.c,%.o, $(CSRC))

#Taken from Makefile.old
srcdir = .
top_srcdir = ../..
top_builddir = ../..
INCLUDES = -I$(srcdir)/..
AM_CFLAGS += -DNDEBUG
DEFS = -DHAVE_CONFIG_H
DEFAULT_INCLUDES =  -I. -I$(srcdir) -I$(top_builddir)
CFLAGS += $(AM_CFLAGS)


#***


all: $(OBJS) $(LIBMODULES)

$(LIBMODULES): ar-target

ar-target: $(OBJS)
	$(AR) $(ARFLAGS) $(LIBMODULES) $(OBJS)
	$(RANLIB) $(LIBMODULES)
	$(INSTALL) -d $(TOPDIR)lib
	$(RM) $(TOPDIR)lib/$(LIBMODULES)
	$(INSTALL) -m 644 $(LIBMODULES) $(TOPDIR)lib


$(OBJS): %.o : %.c
	$(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(CFLAGS) -c $< -o $@
	$(STRIPTOOL) -x -R .note -R .comment $*.o

$(OBJ): Makefile

shared: all
	$(LD) $(LDFLAGS) -soname=$(LIBMODULES_SHARED).$(MAJOR_VERSION) \
		-o $(LIBMODULES_SHARED_FULLNAME) --whole-archive $(LIBMODULES) \
		--no-whole-archive $(TOPDIR)libc/misc/internals/interp.o \
		-L$(TOPDIR)lib -lc $(LDADD_LIBFLOAT) $(LIBGCC);
	$(INSTALL) -d $(TOPDIR)lib
	$(RM) $(TOPDIR)lib/$(LIBMODULES_SHARED_FULLNAME) $(TOPDIR)lib/$(LIBMODULES_SHARED).$(MAJOR_VERSION)
	$(INSTALL) -m 644 $(LIBMODULES_SHARED_FULLNAME) $(TOPDIR)lib
	$(LN) -sf $(LIBMODULES_SHARED_FULLNAME) $(TOPDIR)lib/$(LIBMODULES_SHARED)
	$(LN) -sf $(LIBMODULES_SHARED_FULLNAME) $(TOPDIR)lib/$(LIBMODULES_SHARED).$(MAJOR_VERSION)


clean: 
	$(RM) *.[oa] *~ core $(LIBMODULES_SHARED)* $(LIBMODULES_SHARED_FULLNAME)*
