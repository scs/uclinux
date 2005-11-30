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

TOPDIR=../
include $(TOPDIR)Rules.mak

LIBIDTAG=libidtag.a
LIBIDTAG_SHARED=libidtag.so
LIBIDTAG_SHARED_FULLNAME=libidtag-$(MAJOR_VERSION).$(MINOR_VERSION).$(SUBLEVEL).so


#Taken from Makefile.old
srcdir = .
top_srcdir = .
top_builddir = .
CSRC = version.c ucs4.c latin1.c utf16.c utf8.c parse.c render.c field.c frametype.c compat.c genre.c frame.c crc.c util.c tag.c file.c 
FPM = -DFPM_DEFAULT
INCLUDES = $(FPM) $(ASO)
DEFS = -DHAVE_CONFIG_H
DEFAULT_INCLUDES =  -I. -I$(srcdir) -I../../lib/zlib

CFLAGS += -Wall -g -O2 
OBJS=$(patsubst %.c,%.o, $(CSRC))


#***


all: $(OBJS) $(LIBIDTAG)

$(LIBIDTAG): ar-target

ar-target: $(OBJS)
	$(AR) $(ARFLAGS) $(LIBIDTAG) $(OBJS)
	$(RANLIB) $(LIBIDTAG)
	$(INSTALL) -d $(TOPDIR)lib
	$(RM) $(TOPDIR)lib/$(LIBIDTAG)
	$(INSTALL) -m 644 $(LIBIDTAG) $(TOPDIR)lib


$(OBJS): %.o : %.c
	$(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(CFLAGS) -c $< -o $@
	$(STRIPTOOL) -x -R .note -R .comment $*.o

$(OBJ): Makefile

romfs:

shared: all
	$(LD) $(LDFLAGS) -soname=$(LIBIDTAG_SHARED).$(MAJOR_VERSION) \
		-o $(LIBIDTAG_SHARED_FULLNAME) --whole-archive $(LIBIDTAG) \
		--no-whole-archive $(TOPDIR)libc/misc/internals/interp.o \
		-L$(TOPDIR)lib -lc $(LDADD_LIBFLOAT) $(LIBGCC);
	$(INSTALL) -d $(TOPDIR)lib
	$(RM) $(TOPDIR)lib/$(LIBIDTAG_SHARED_FULLNAME) $(TOPDIR)lib/$(LIBIDTAG_SHARED).$(MAJOR_VERSION)
	$(INSTALL) -m 644 $(LIBIDTAG_SHARED_FULLNAME) $(TOPDIR)lib
	$(LN) -sf $(LIBIDTAG_SHARED_FULLNAME) $(TOPDIR)lib/$(LIBIDTAG_SHARED)
	$(LN) -sf $(LIBIDTAG_SHARED_FULLNAME) $(TOPDIR)lib/$(LIBIDTAG_SHARED).$(MAJOR_VERSION)


clean: 
	$(RM) *.[oa] *~ core $(LIBIDTAG_SHARED)* $(LIBIDTAG_SHARED_FULLNAME)*
