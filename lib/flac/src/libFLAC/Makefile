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

LIBFLAC=libflac.a
LIBFLAC_SHARED=libflac.so
LIBFLAC_SHARED_FULLNAME=libflac-$(MAJOR_VERSION).$(MINOR_VERSION).$(SUBLEVEL).so


#Taken from Makefile.old

srcdir = .
top_srcdir = ../..
top_builddir = ../..
#CFLAGS += -I$(top_builddir) -I$(srcdir)/include -I$(top_srcdir)/include -O3 -DNDEBUG -fomit-frame-pointer -funroll-loops -finline-functions -Wall -W -Winline -DFLaC__INLINE=__inline__ -g -O2 $(DEBUGCFLAGS)



CFLAGS += -I$(top_builddir) -I$(srcdir)/include -I$(top_srcdir)/include -DNDEBUG -fomit-frame-pointer -funroll-loops -finline-functions -Wall -W -Winline -DFLaC__INLINE=__inline__ 

CSRC =  bitbuffer.c  bitmath.c  cpu.c crc.c file_decoder.c file_encoder.c fixed.c format.c lpc.c md5.c memory.c metadata_iterators.c  metadata_object.c seekable_stream_decoder.c seekable_stream_encoder.c stream_decoder.c stream_encoder.c stream_encoder_framing.c

DEFS = -DHAVE_CONFIG_H
DEFAULT_INCLUDES =  -I. -I$(srcdir) -I$(top_builddir)

OBJS=$(patsubst %.c,%.o, $(CSRC))


#***


all: $(OBJS) $(LIBFLAC)

$(LIBFLAC): ar-target

ar-target: $(OBJS)
	$(AR) $(ARFLAGS) $(LIBFLAC) $(OBJS)
	$(RANLIB) $(LIBFLAC)
	$(INSTALL) -d $(TOPDIR)lib
	$(RM) $(TOPDIR)lib/$(LIBFLAC)
	$(INSTALL) -m 644 $(LIBFLAC) $(TOPDIR)lib


$(OBJS): %.o : %.c
	$(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(CFLAGS) -c $< -o $@
	$(STRIPTOOL) -x -R .note -R .comment $*.o

$(OBJ): Makefile

shared: all
	$(LD) $(LDFLAGS) -soname=$(LIBFLAC_SHARED).$(MAJOR_VERSION) \
		-o $(LIBFLAC_SHARED_FULLNAME) --whole-archive $(LIBFLAC) \
		--no-whole-archive $(TOPDIR)libc/misc/internals/interp.o \
		-L$(TOPDIR)lib -lc $(LDADD_LIBFLOAT) $(LIBGCC);
	$(INSTALL) -d $(TOPDIR)lib
	$(RM) $(TOPDIR)lib/$(LIBFLAC_SHARED_FULLNAME) $(TOPDIR)lib/$(LIBFLAC_SHARED).$(MAJOR_VERSION)
	$(INSTALL) -m 644 $(LIBFLAC_SHARED_FULLNAME) $(TOPDIR)lib
	$(LN) -sf $(LIBFLAC_SHARED_FULLNAME) $(TOPDIR)lib/$(LIBFLAC_SHARED)
	$(LN) -sf $(LIBFLAC_SHARED_FULLNAME) $(TOPDIR)lib/$(LIBFLAC_SHARED).$(MAJOR_VERSION)


clean: 
	$(RM) *.[oa] *~ core $(LIBFLAC_SHARED)* $(LIBFLAC_SHARED_FULLNAME)*
