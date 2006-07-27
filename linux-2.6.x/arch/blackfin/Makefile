#
# arch/blackfin/Makefile
#
# This file is subject to the terms and conditions of the GNU General Public
# License.  See the file "COPYING" in the main directory of this archive
# for more details.
#

CROSS_COMPILE	:= bfin-uclinux-
LDFLAGS_vmlinux	:= -X
LDFLAGS_BLOB	:=--format binary -elf32-bfin
OBJCOPYFLAGS	:=-O binary -R .note -R .comment -S
GZFLAGS		:=-9
CFLAGS		+=-D__linux__
BFIN_TARGET 	= vmlinux

CFLAGS_MODULE   += -mlong-calls
KALLSYMS	+= --symbol-prefix=_

comma = ,

# These are the default values for independt
PROCESSOR	:= bf5xx

# setup the machine name and the machine dependent settings

machine-$(CONFIG_BF533) := bf533
machine-$(CONFIG_BF532) := bf533
machine-$(CONFIG_BF531) := bf533
machine-$(CONFIG_BF534) := bf537
machine-$(CONFIG_BF536) := bf537
machine-$(CONFIG_BF535) := bf535
machine-$(CONFIG_BF537) := bf537
machine-$(CONFIG_BF561) := bf561

# set the environment variables and export
MACHINE  := $(machine-y)

export	MACHINE PROCESSOR GZFLAGS CFLAGS_BOOT

CLEAN_FILES += include/asm-$(ARCH)/asm-offsets.h \
	       arch/$(ARCH)/kernel/asm-offsets.s include/asm-$(ARCH)/mach include/asm-blackfin/.mach

# The machine has its own head.S

head-y	:= arch/$(ARCH)/mach-$(MACHINE)/head.o

# add the init_task to head

head-y		+= arch/$(ARCH)/kernel/init_task.o

core-y		+= arch/$(ARCH)/kernel/ arch/$(ARCH)/mm/

core-y		+= arch/$(ARCH)/mach-common/

# must be linked after kernel/
drivers-$(CONFIG_OPROFILE)              += arch/$(ARCH)/oprofile/


# If we have a machine-specific directory, then include it in the build.
ifneq ($(machine-y),)
core-y		+= arch/$(ARCH)/mach-$(MACHINE)/
core-y		+= arch/$(ARCH)/mach-$(MACHINE)/boards/
endif

libs-y		+= arch/$(ARCH)/lib/

#	Update machine arch symlinks if something which affects
#	them changed.  We use .mach to indicate when they were updated
#	last, otherwise make uses the target directory mtime.

include/asm-blackfin/.mach: $(wildcard include/config/arch/*.h) include/config/MARKER
	@echo '  SYMLINK include/asm-$(ARCH)/mach-$(MACHINE) -> include/asm-$(ARCH)/mach'
ifneq ($(KBUILD_SRC),)
	$(Q)mkdir -p include/asm-$(ARCH)
	$(Q)ln -fsn $(srctree)/include/asm-$(ARCH)/mach-$(MACHINE) include/asm-$(ARCH)/mach
else
	$(Q)ln -fsn mach-$(MACHINE) include/asm-$(ARCH)/mach
endif
	@touch $@

archprepare: include/asm-blackfin/.mach
archclean:

