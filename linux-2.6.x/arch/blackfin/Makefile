#
# arch/bfinnommu/Makefile
#
# This file is subject to the terms and conditions of the GNU General Public
# License.  See the file "COPYING" in the main directory of this archive
# for more details.
#
# Copyright (C) 2004 LG Soft India 

CROSS_COMPILE	:= bfin-elf-
LDFLAGS_vmlinux	:= -p -X
LDFLAGS_BLOB	:=--format binary -elf32-bfin
OBJCOPYFLAGS	:=-O binary -R .note -R .comment -S
GZFLAGS		:=-9
CFLAGS		+=-fno-builtin -D__linux__
CPPFLAGS	+=-mno-underscore
BFIN_TARGET 	= vmlinux
#CFLAGS		:=$(CFLAGS:-O2=-Os)

ifeq ($(CONFIG_FRAME_POINTER),y)
CFLAGS		+=-fno-omit-frame-pointer -mapcs -mno-sched-prolog
endif

comma = ,

# These are the default values for independt
PROCESSOR	:= bf533 
textaddr-y	:= 0x00001000	# default text address

# setup the machine name and the machine dependent settings
machine-y 	:= bf533

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
all: $(BFIN_TARGET)	
	mv vmlinux linux.dxe 

include/asm-$(ARCH)/asm-offsets.h: arch/$(ARCH)/kernel/asm-offsets.s \
				   include/asm include/linux/version.h \
				   include/config/MARKER
	$(call filechk,gen-asm-offsets)


