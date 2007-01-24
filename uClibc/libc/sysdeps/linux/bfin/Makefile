# Makefile for uClibc
#
# Copyright (C) 2000-2003 Erik Andersen <andersen@uclibc.org>
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

TOPDIR=../../../../
include $(TOPDIR)Rules.mak
ASFLAGS=$(CFLAGS)

CRT0_SRC = crt0.S
CRT0_OBJ = crt0.o crt1.o
SCRT0_OBJ = $(patsubst %,S%, $(CRT0_OBJ))
CTOR_TARGETS = crti.o crtn.o
CRTRELOC_OBJ = crtreloc.o

SSRC= __longjmp.S setjmp.S bsd-_setjmp.S vfork.S
SOBJS=$(patsubst %.S,%.o, $(SSRC))

CSRC=brk.c clone.c syscall.c mmap.c \
	sram-alloc.c sram-free.c dma-memcpy.c

COBJS=$(patsubst %.c,%.o, $(CSRC))

OBJS=$(SOBJS) $(MOBJ) $(COBJS)

OBJ_LIST=../../../obj.sysdeps.$(TARGET_ARCH)

all: $(OBJ_LIST)

$(OBJ_LIST): $(OBJS) $(CRT0_OBJ) $(SCRT0_OBJ) $(CTOR_TARGETS) $(CRTRELOC_OBJ)
	echo $(patsubst %, sysdeps/linux/$(TARGET_ARCH)/%, $(OBJS)) > $(OBJ_LIST)
	$(INSTALL) -d $(TOPDIR)lib/
	cp $(CRT0_OBJ) $(SCRT0_OBJ) $(CTOR_TARGETS) $(CRTRELOC_OBJ) $(TOPDIR)lib/

$(CRT0_OBJ): $(CRT0_SRC)
	$(CC) $(ASFLAGS) -DL_$* -r -nostdlib $< -o $*.o
	$(STRIPTOOL) -x -R .note -R .comment $*.o

crtreloc.o: crtreloc.c
	$(CC) $(CFLAGS) -c $< -o $@

$(SCRT0_OBJ): $(CRT0_SRC)
	$(CC) $(ASFLAGS) $(PIEFLAG) -D__pie__ -DL_$* -r -nostdlib $< -o $*.o
	$(STRIPTOOL) -x -R .note -R .comment $*.o

# Scrtreloc.o: crtreloc.c
# 	$(CC) $(CFLAGS) $(PIEFLAG) -c $< -o $@

$(SOBJS): %.o : %.S
	$(CC) $(CFLAGS) -c $< -o $@
	$(STRIPTOOL) -x -R .note -R .comment $*.o

$(COBJS): %.o : %.c
	$(CC) $(CFLAGS) -c $< -o $@
	$(STRIPTOOL) -x -R .note -R .comment $*.o

headers:
	$(LN) -fs ../libc/sysdeps/linux/bfin/bfin_sram.h $(TOPDIR)/include/

clean:
	$(RM) *.[oa] *~ core
	$(RM) bits/sysnum.h
	$(RM) $(TOPDIR)lib/crt0.o

