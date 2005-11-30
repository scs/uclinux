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

LIBMAD=libmad.a
LIBMAD_SHARED=libmad.so
LIBMAD_SHARED_FULLNAME=libmad-$(MAJOR_VERSION).$(MINOR_VERSION).$(SUBLEVEL).so


#Taken from Makefile.old
srcdir = .
top_srcdir = .
top_builddir = .
CSRC = version.c fixed.c bit.c timer.c stream.c frame.c synth.c decoder.c layer12.c layer3.c huffman.c
FPM = -DFPM_DEFAULT
INCLUDES = $(FPM) $(ASO)
DEFS = -DHAVE_CONFIG_H
DEFAULT_INCLUDES =  -I. -I$(srcdir) -I.

CFLAGS += -Wall -g  -fforce-mem -fforce-addr -fthread-jumps -fcse-follow-jumps -fcse-skip-blocks -fexpensive-optimizations -fregmove -fschedule-insns2 -fstrength-reduce
OBJS=$(patsubst %.c,%.o, $(CSRC))


#***


all: $(OBJS) $(LIBMAD)

$(LIBMAD): ar-target

ar-target: $(OBJS)
	$(AR) $(ARFLAGS) $(LIBMAD) $(OBJS)
	$(RANLIB) $(LIBMAD)
	$(INSTALL) -d $(TOPDIR)lib
	$(RM) $(TOPDIR)lib/$(LIBMAD)
	$(INSTALL) -m 644 $(LIBMAD) $(TOPDIR)lib


$(OBJS): %.o : %.c
	$(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(CFLAGS) -c $< -o $@
	$(STRIPTOOL) -x -R .note -R .comment $*.o

$(OBJ): Makefile

romfs:

shared: all
	$(LD) $(LDFLAGS) -soname=$(LIBMAD_SHARED).$(MAJOR_VERSION) \
		-o $(LIBMAD_SHARED_FULLNAME) --whole-archive $(LIBMAD) \
		--no-whole-archive $(TOPDIR)libc/misc/internals/interp.o \
		-L$(TOPDIR)lib -lc $(LDADD_LIBFLOAT) $(LIBGCC);
	$(INSTALL) -d $(TOPDIR)lib
	$(RM) $(TOPDIR)lib/$(LIBMAD_SHARED_FULLNAME) $(TOPDIR)lib/$(LIBMAD_SHARED).$(MAJOR_VERSION)
	$(INSTALL) -m 644 $(LIBMAD_SHARED_FULLNAME) $(TOPDIR)lib
	$(LN) -sf $(LIBMAD_SHARED_FULLNAME) $(TOPDIR)lib/$(LIBMAD_SHARED)
	$(LN) -sf $(LIBMAD_SHARED_FULLNAME) $(TOPDIR)lib/$(LIBMAD_SHARED).$(MAJOR_VERSION)


clean: 
	$(RM) *.[oa] *~ core $(LIBMAD_SHARED)* $(LIBMAD_SHARED_FULLNAME)*
