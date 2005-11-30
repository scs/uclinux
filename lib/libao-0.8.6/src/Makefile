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

LIBAO=libao.a
LIBAO_SHARED=libao.so
LIBAO_SHARED_FULLNAME=libmad-$(MAJOR_VERSION).$(MINOR_VERSION).$(SUBLEVEL).so


#Taken from Makefile.old
srcdir = .
top_srcdir = .
top_builddir = .
CSRC = audio_out.c config.c ao_null.c ao_wav.c ao_au.c ao_raw.c ao_aixs.c ao_private.h
FPM = -DFPM_DEFAULT
INCLUDES = $(FPM) $(ASO)
DEFS = -DHAVE_CONFIG_H
DEFAULT_INCLUDES =  -I. -I$(srcdir) -I. -I../include

CFLAGS += -Wall -g  -fforce-mem -fforce-addr -fthread-jumps -fcse-follow-jumps -fcse-skip-blocks -fexpensive-optimizations -fregmove -fschedule-insns2 -fstrength-reduce
OBJS=$(patsubst %.c,%.o, $(CSRC))


#***


all: $(OBJS) $(LIBAO)

$(LIBAO): ar-target

ar-target: $(OBJS)
	$(AR) $(ARFLAGS) $(LIBAO) $(OBJS)
	$(RANLIB) $(LIBAO)
	$(INSTALL) -d $(TOPDIR)lib
	$(RM) $(TOPDIR)lib/$(LIBAO)
	$(INSTALL) -m 644 $(LIBAO) $(TOPDIR)lib


$(OBJS): %.o : %.c
	$(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(CFLAGS) -c $< -o $@
	$(STRIPTOOL) -x -R .note -R .comment $*.o

$(OBJ): Makefile

shared: all
	$(LD) $(LDFLAGS) -soname=$(LIBAO_SHARED).$(MAJOR_VERSION) \
		-o $(LIBAO_SHARED_FULLNAME) --whole-archive $(LIBAO) \
		--no-whole-archive $(TOPDIR)libc/misc/internals/interp.o \
		-L$(TOPDIR)lib -lc $(LDADD_LIBFLOAT) $(LIBGCC);
	$(INSTALL) -d $(TOPDIR)lib
	$(RM) $(TOPDIR)lib/$(LIBAO_SHARED_FULLNAME) $(TOPDIR)lib/$(LIBAO_SHARED).$(MAJOR_VERSION)
	$(INSTALL) -m 644 $(LIBAO_SHARED_FULLNAME) $(TOPDIR)lib
	$(LN) -sf $(LIBAO_SHARED_FULLNAME) $(TOPDIR)lib/$(LIBAO_SHARED)
	$(LN) -sf $(LIBAO_SHARED_FULLNAME) $(TOPDIR)lib/$(LIBAO_SHARED).$(MAJOR_VERSION)


clean: 
	$(RM) *.[oa] *~ core $(LIBAO_SHARED)* $(LIBAO_SHARED_FULLNAME)*
