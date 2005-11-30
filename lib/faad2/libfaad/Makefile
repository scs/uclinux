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

TOPDIR=../../
include $(TOPDIR)Rules.mak

LIBFAAD=libfaad.a
LIBFAAD_SHARED=libfaad.so
LIBFAAD_SHARED_FULLNAME=libfaad-$(MAJOR_VERSION).$(MINOR_VERSION).$(SUBLEVEL).so


#Taken from Makefile.old
rcdir = .
top_srcdir = ..
top_builddir = ..
include_HEADERS = ../include/faad.h
libfaad_la_SOURCES = bits.c cfft.c decoder.c drc.c \
error.c filtbank.c \
ic_predict.c is.c lt_predict.c mdct.c mp4.c ms.c output.c pns.c \
pulse.c specrec.c syntax.c tns.c hcr.c huffman.c \
rvlc.c ssr.c ssr_fb.c ssr_ipqf.c common.c \
sbr_dct.c sbr_e_nf.c sbr_fbt.c sbr_hfadj.c sbr_hfgen.c \
sbr_huff.c sbr_qmf.c sbr_syntax.c sbr_tf_grid.c sbr_dec.c 

DEFS = -DHAVE_CONFIG_H
DEFAULT_INCLUDES =  -I. -I$(srcdir) -I$(top_builddir)
CFLAGS +=  -O2


#***
CSRC = $(libfaad_la_SOURCES)
OBJS=$(patsubst %.c,%.o, $(CSRC))

all: $(OBJS) $(LIBFAAD)

$(LIBFAAD): ar-target

ar-target: $(OBJS)
	$(AR) $(ARFLAGS) $(LIBFAAD) $(OBJS)
	$(RANLIB) $(LIBFAAD)
	$(INSTALL) -d $(TOPDIR)lib
	$(RM) $(TOPDIR)lib/$(LIBFAAD)
	$(INSTALL) -m 644 $(LIBFAAD) $(TOPDIR)lib


$(OBJS): %.o : %.c
	$(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(CFLAGS) -c $< -o $@
	$(STRIPTOOL) -x -R .note -R .comment $*.o

$(OBJ): Makefile

shared: all
	$(LD) $(LDFLAGS) -soname=$(LIBFAAD_SHARED).$(MAJOR_VERSION) \
		-o $(LIBFAAD_SHARED_FULLNAME) --whole-archive $(LIBFAAD) \
		--no-whole-archive $(TOPDIR)libc/misc/internals/interp.o \
		-L$(TOPDIR)lib -lc $(LDADD_LIBFLOAT) $(LIBGCC);
	$(INSTALL) -d $(TOPDIR)lib
	$(RM) $(TOPDIR)lib/$(LIBFAAD_SHARED_FULLNAME) $(TOPDIR)lib/$(LIBFAAD_SHARED).$(MAJOR_VERSION)
	$(INSTALL) -m 644 $(LIBFAAD_SHARED_FULLNAME) $(TOPDIR)lib
	$(LN) -sf $(LIBFAAD_SHARED_FULLNAME) $(TOPDIR)lib/$(LIBFAAD_SHARED)
	$(LN) -sf $(LIBFAAD_SHARED_FULLNAME) $(TOPDIR)lib/$(LIBFAAD_SHARED).$(MAJOR_VERSION)


clean: 
	$(RM) *.[oa] *~ core $(LIBFAAD_SHARED)* $(LIBFAAD_SHARED_FULLNAME)*
