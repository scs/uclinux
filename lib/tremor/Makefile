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
# include $(TOPDIR)Rules.mak
INSTALL=install

LIBTREMOR=libtremor.a
LIBTREMOR_SHARED=libtremor.so
LIBTREMOR_SHARED_FULLNAME=libtremor-$(MAJOR_VERSION).$(MINOR_VERSION).$(SUBLEVEL).so

CSRC = bitwise.c block.c codebook.c floor0.c floor1.c framing.c info.c mapping0.c mdct.c registry.c res012.c sharedbook.c synthesis.c vorbisfile.c window.c


OBJS=$(patsubst %.c,%.o, $(CSRC))

all: $(OBJS) $(LIBTREMOR)

$(LIBTREMOR): ar-target

ar-target: $(OBJS)
	$(AR) $(ARFLAGS) $(LIBTREMOR) $(OBJS)
	$(INSTALL) -d $(TOPDIR)lib
	$(RM) $(TOPDIR)lib/$(LIBTREMOR)
	$(INSTALL) -m 644 $(LIBTREMOR) $(TOPDIR)lib

$(OBJS): %.o : %.c
	$(CC) $(CFLAGS) -c $< -o $@
	$(STRIPTOOL) -x -R .note -R .comment $*.o

$(OBJ): Makefile

romfs:

shared: all
	$(LD) $(LDFLAGS) -soname=$(LIBTREMOR_SHARED).$(MAJOR_VERSION) \
		-o $(LIBTREMOR_SHARED_FULLNAME) --whole-archive $(LIBTREMOR) \
		--no-whole-archive $(TOPDIR)libc/misc/internals/interp.o \
		-L$(TOPDIR)lib -lc $(LDADD_LIBFLOAT) $(LIBGCC);
	$(INSTALL) -d $(TOPDIR)lib
	$(RM) $(TOPDIR)lib/$(LIBTREMOR_SHARED_FULLNAME) $(TOPDIR)lib/$(LIBTREMOR_SHARED).$(MAJOR_VERSION)
	$(INSTALL) -m 644 $(LIBTREMOR_SHARED_FULLNAME) $(TOPDIR)lib
	$(LN) -sf $(LIBTREMOR_SHARED_FULLNAME) $(TOPDIR)lib/$(LIBTREMOR_SHARED)
	$(LN) -sf $(LIBTREMOR_SHARED_FULLNAME) $(TOPDIR)lib/$(LIBTREMOR_SHARED).$(MAJOR_VERSION)

clean: 
	$(RM) *.[oa] *~ core $(LIBTREMOR_SHARED)* $(LIBTREMOR_SHARED_FULLNAME)*
