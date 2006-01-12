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
# include $(TOPDIR)Rules.mak
INSTALL=install

LIBAUDIOFILE=libaudiofile.a
LIBAUDIOFILE_SHARED=libaudiofile.so
LIBAUDIOFILE_SHARED_FULLNAME=libaudiofile-$(MAJOR_VERSION).$(MINOR_VERSION).$(SUBLEVEL).so


#Taken from Makefile.old
srcdir = .
top_builddir = ..
top_srcdir = ..

CSRC =  openclose.c setup.c format.c data.c pcm.c  error.c byteorder.c af_vfs.c  util.c debug.c aupv.c units.c compression.c  aes.c instrument.c loop.c marker.c misc.c track.c query.c  raw.c  aiff.c aiffwrite.c extended.c next.c nextwrite.c wave.c wavewrite.c  ircam.c ircamwrite.c  avr.c avrwrite.c  iff.c iffwrite.c   nist.c nistwrite.c  g711.c  modules.c 

OBJS=$(patsubst %.c,%.o, $(CSRC))

AM_CFLAGS = -DNDEBUG
DEFS = -DHAVE_CONFIG_H
DEFAULT_INCLUDES =  -I. -I$(srcdir) -I$(top_builddir)
CFLAGS +=  $(AM_CFLAGS)

#***


all: subdirs all-am 

subdirs: 
	make -C modules


all-am:  $(OBJS) $(LIBAUDIOFILE)


$(LIBAUDIOFILE): ar-target

ar-target: $(OBJS)
	$(AR) $(ARFLAGS) $(LIBAUDIOFILE) $(OBJS) #./modules/libmodules.a
	$(RANLIB) $(LIBAUDIOFILE)
	$(INSTALL) -d $(TOPDIR)lib
	$(RM) $(TOPDIR)lib/$(LIBAUDIOFILE)
	$(INSTALL) -m 644 $(LIBAUDIOFILE) $(TOPDIR)lib


$(OBJS): %.o : %.c
	$(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(CFLAGS) -c $< -o $@
	$(STRIPTOOL) -x -R .note -R .comment $*.o

$(OBJ): Makefile

shared: all
	$(LD) $(LDFLAGS) -soname=$(LIBAUDIOFILE_SHARED).$(MAJOR_VERSION) \
		-o $(LIBAUDIOFILE_SHARED_FULLNAME) --whole-archive $(LIBAUDIOFILE) \
		--no-whole-archive $(TOPDIR)libc/misc/internals/interp.o \
		-L$(TOPDIR)lib -lc $(LDADD_LIBFLOAT) $(LIBGCC);
	$(INSTALL) -d $(TOPDIR)lib
	$(RM) $(TOPDIR)lib/$(LIBAUDIOFILE_SHARED_FULLNAME) $(TOPDIR)lib/$(LIBAUDIOFILE_SHARED).$(MAJOR_VERSION)
	$(INSTALL) -m 644 $(LIBAUDIOFILE_SHARED_FULLNAME) $(TOPDIR)lib
	$(LN) -sf $(LIBAUDIOFILE_SHARED_FULLNAME) $(TOPDIR)lib/$(LIBAUDIOFILE_SHARED)
	$(LN) -sf $(LIBAUDIOFILE_SHARED_FULLNAME) $(TOPDIR)lib/$(LIBAUDIOFILE_SHARED).$(MAJOR_VERSION)


clean: 
	$(RM) *.[oa] *~ core $(LIBAUDIOFILE_SHARED)* $(LIBAUDIOFILE_SHARED_FULLNAME)*
	make -C modules clean
