#
# arch/bfinnommu/Makefile
#
# This file is subject to the terms and conditions of the GNU General Public
# License.  See the file "COPYING" in the main directory of this archive
# for more details.
# Derived from ARM nommu patches
#
# Copyright (C) 2004 LG Soft India 
# Copyright (C) 1995-2001 by Russell King

LDFLAGS_vmlinux	:= -p -X
LDFLAGS_BLOB	:=--format binary -elf32-bfin
OBJCOPYFLAGS	:=-O binary -R .note -R .comment -S
GZFLAGS		:=-9
CFLAGS		+=-fno-builtin -D__linux__
CPPFLAGS	+=-mno-underscore
#CFLAGS		:=$(CFLAGS:-O2=-Os)

ifeq ($(CONFIG_FRAME_POINTER),y)
CFLAGS		+=-fno-omit-frame-pointer -mapcs -mno-sched-prolog
endif

comma = ,

# These are the default values for independt
PROCESSOR	:= bf533 
textaddr-y	:= 0x00001000	# default text address

# setup the machine name and the machine dependent settings
machine-y 		:= bf533

# set the environment variables and export
MACHINE  := $(machine-y)
TEXTADDR := $(textaddr-y)
  
export	MACHINE PROCESSOR TEXTADDR GZFLAGS CFLAGS_BOOT

# Does the machine has its own head.S ?

head-y	:= arch/bfinnommu/mach-bf533/head.o 

# add the init_task to head

head-y		+= arch/bfinnommu/kernel/init_task.o

# If we have a machine-specific directory, then include it in the build.
core-y		+= arch/bfinnommu/kernel/ arch/bfinnommu/mm/

core-y		+= arch/bfinnommu/mach-bf533/

libs-y		+= arch/bfinnommu/lib/

# Default target when executing plain make

all: uCImage

boot := arch/bfinnommu/boot

#	Update machine arch and proc symlinks if something which affects
#	them changed.  We use .arch and .proc to indicate when they were
#	updated last, otherwise make uses the target directory mtime.

# Convert bzImage to zImage
bzImage: vmlinux
	$(Q)$(MAKE) $(build)=$(boot) $(boot)/zImage

zImage Image bootpImage uImage: vmlinux
	$(Q)$(MAKE) $(build)=$(boot) $(boot)/$@

uCImage: vmlinux linux.bin

linux.bin: vmlinux FORCE
	@$(OBJCOPY) $(OBJCOPYFLAGS) vmlinux $@
	@echo '  Kernel: $@ is ready'

zinstall install: vmlinux
	$(Q)$(MAKE) $(build)=$(boot) $@

prepare: include/asm-$(ARCH)/asm-offsets.h

include/asm-$(ARCH)/asm-offsets.h: arch/$(ARCH)/kernel/asm-offsets.s \
				   include/asm include/linux/version.h \
				   include/config/MARKER
	$(call filechk,gen-asm-offsets)


