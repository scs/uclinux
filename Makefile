############################################################################

#
# Makefile -- Top level dist makefile.
#
# Copyright (c) 2001-2007, SnapGear (www.snapgear.com)
# Copyright (c) 2001, Lineo
#

VERSIONPKG = 3.2.0
VERSIONSTR = $(CONFIG_VENDOR)/$(CONFIG_PRODUCT) Version $(VERSIONPKG)

############################################################################
#
# Lets work out what the user wants, and if they have configured us yet
#

ifeq (.config,$(wildcard .config))
include .config

all: tools subdirs romfs image
else
all: config_error
endif

############################################################################
#
# Get the core stuff worked out
#

LINUXDIR = $(CONFIG_LINUXDIR)
LIBCDIR  = $(CONFIG_LIBCDIR)
ROOTDIR  = $(shell pwd)
PATH	 := $(ROOTDIR)/tools:$(PATH)
HOSTCC   = cc
IMAGEDIR = $(ROOTDIR)/images
RELDIR   = $(ROOTDIR)/release
ROMFSDIR = $(ROOTDIR)/romfs
PRODUCTDIR = $(ROOTDIR)/vendors/$(CONFIG_VENDOR)/$(CONFIG_PRODUCT)
ROMFSINST= romfs-inst.sh
SCRIPTSDIR = $(ROOTDIR)/config/kconfig
STAGEDIR = $(ROOTDIR)/staging
DOWNLOADDIR = $(ROOTDIR)/download
TFTPDIR    = /tftpboot
BUILD_START_STRING ?= $(shell date "+%a, %d %b %Y %T %z")
ifndef NON_SMP_BUILD
HOST_NCPU := $(shell if [ -f /proc/cpuinfo ]; then n=`grep -c processor /proc/cpuinfo`; if [ $$n -gt 1 ];then expr $$n \* 2; else echo $$n; fi; else echo 1; fi)
else
HOST_NCPU := 1
endif

LINUX_CONFIG  = $(ROOTDIR)/$(LINUXDIR)/.config
CONFIG_CONFIG = $(ROOTDIR)/config/.config
MODULES_CONFIG = $(ROOTDIR)/modules/.config
-include $(CONFIG_CONFIG)
-include $(LINUX_CONFIG)

CONFIG_SHELL := $(shell if [ -x "$$BASH" ]; then echo $$BASH; \
	  else if [ -x /bin/bash ]; then echo /bin/bash; \
	  else echo sh; fi ; fi)

ifeq (config.arch,$(wildcard config.arch))
ifeq ($(filter %_default, $(MAKECMDGOALS)),)
include config.arch
ARCH_CONFIG = $(ROOTDIR)/config.arch
export ARCH_CONFIG
endif
endif

# May use a different compiler for the kernel
KERNEL_CROSS_COMPILE ?= $(CROSS_COMPILE)
ifneq ($(SUBARCH),)
# Using UML, so make the kernel and non-kernel with different ARCHs
MAKEARCH = $(MAKE) ARCH=$(SUBARCH) CROSS_COMPILE=$(CROSS_COMPILE)
MAKEARCH_KERNEL = $(MAKE) ARCH=$(ARCH) SUBARCH=$(SUBARCH) CROSS_COMPILE=$(KERNEL_CROSS_COMPILE)
else
MAKEARCH = $(MAKE) ARCH=$(ARCH)
MAKEARCH_KERNEL = $(MAKE) ARCH=$(ARCH) CROSS_COMPILE=$(KERNEL_CROSS_COMPILE)
endif

DIRS    = $(VENDOR_TOPDIRS) include lib include user

# With the staging dir, we don't need to process the "include" dir
DIRS   := $(filter-out include,$(DIRS))

# some older configure's do not check for proper pkg-config named binaries
PKG_CONFIG = $(ROOTDIR)/tools/$(CROSS_COMPILE)pkg-config
export PKG_CONFIG

export VENDOR PRODUCT ROOTDIR LINUXDIR HOSTCC CONFIG_SHELL
export CONFIG_CONFIG LINUX_CONFIG MODULES_CONFIG ROMFSDIR SCRIPTSDIR
export VERSIONPKG VERSIONSTR ROMFSINST PATH IMAGEDIR RELDIR RELFILES TFTPDIR
export BUILD_START_STRING PRODUCTDIR
export HOST_NCPU

.PHONY: tools
tools: ucfront cksum
	chmod +x tools/romfs-inst.sh tools/modules-alias.sh

.PHONY: ucfront
ucfront: tools/ucfront/*.c
no-ucfront-for-blackfin:
	$(MAKE) -C tools/ucfront
	ln -sf $(ROOTDIR)/tools/ucfront/ucfront tools/ucfront-gcc
	ln -sf $(ROOTDIR)/tools/ucfront/ucfront tools/ucfront-g++
	ln -sf $(ROOTDIR)/tools/ucfront/ucfront-ld tools/ucfront-ld

.PHONY: cksum
cksum: tools/cksum
tools/cksum: tools/sg-cksum/*.c
	$(MAKE) -C tools/sg-cksum
	ln -sf $(ROOTDIR)/tools/sg-cksum/cksum tools/cksum

.PHONY: sstrip
#tools: sstrip
sstrip: tools/sstrip
tools/sstrip: tools/sstrip.c
	$(HOSTCC) -Wall -O2 -g -o $@ $<

.PHONY: staging
ifneq ($(CROSS_COMPILE),)
all: staging
tools: staging
staging: \
	tools/$(CROSS_COMPILE)gcc \
	tools/$(CROSS_COMPILE)g++ \
	tools/$(CROSS_COMPILE)cpp \
	tools/$(CROSS_COMPILE)ld \
	tools/$(CROSS_COMPILE)pkg-config
tools/$(CROSS_COMPILE)%:
	ln -sf staging-compiler $@
tools/$(CROSS_COMPILE)pkg-config:
	ln -sf cross-pkg-config $@
else
staging:
	@echo "Error: you have not configured things yet" ; false
endif

############################################################################

#
# Config stuff, we recall ourselves to load the new config.arch before
# running the kernel and other config scripts
#

.PHONY: vendors/Kconfig
vendors/Kconfig:
	find vendors -mindepth 2 '(' -name .svn -prune ')' -o -type f -name Kconfig -print | sed 's:^:source ../:' > vendors/Kconfig

.PHONY: Kconfig
Kconfig: vendors/Kconfig
	@chmod u+x config/mkconfig
	config/mkconfig > Kconfig

include config/Makefile.conf

SCRIPTS_BINARY_config     = conf
SCRIPTS_BINARY_menuconfig = mconf
SCRIPTS_BINARY_qconfig    = qconf
SCRIPTS_BINARY_gconfig    = gconf
SCRIPTS_BINARY_xconfig    = gconf
.PHONY: config menuconfig qconfig gconfig xconfig
menuconfig: mconf
qconfig: qconf
gconfig: gconf
xconfig: $(SCRIPTS_BINARY_xconfig)
config menuconfig qconfig gconfig xconfig: Kconfig conf
	KCONFIG_NOTIMESTAMP=1 $(SCRIPTSDIR)/$(SCRIPTS_BINARY_$@) Kconfig
	@if [ ! -f .config ]; then \
		echo; \
		echo "You have not saved your config, please re-run 'make $@'"; \
		echo; \
		exit 1; \
	 fi
	@chmod u+x config/setconfig
	@config/setconfig defaults
	@if egrep "^CONFIG_DEFAULTS_KERNEL=y" .config > /dev/null; then \
		$(MAKE) linux_$@; \
	 fi
	@if egrep "^CONFIG_DEFAULTS_MODULES=y" .config > /dev/null; then \
		$(MAKE) modules_$@; \
	 fi
	@if egrep "^CONFIG_DEFAULTS_VENDOR=y" .config > /dev/null; then \
		$(MAKE) config_$@; \
	 fi
	@config/setconfig final

.PHONY: remoteconfig
remoteconfig:
#ifndef IP
ifeq ($(IP),)
	@echo "NOTE : 'make remoteconfig' requires a valid IP number, to be set"
	@echo "        example 'make remoteconfig IP=192.168.0.1'"
	@echo "             or 'make remoteconfig IP=address.foo.bar'"
else
	ping -c 1 $(IP)
	rcp root@$(IP):/root/vendor-board-config.gz $(ROOTDIR)/vendor-board-config.gz
	rcp root@$(IP):/proc/config.gz $(LINUX_CONFIG).gz
	rcp root@$(IP):/root/uclinux-config.gz $(CONFIG_CONFIG).gz
	@$(MAKE) -s distclean
	gunzip -f $(ROOTDIR)/vendor-board-config.gz
	mv -f $(ROOTDIR)/vendor-board-config $(ROOTDIR)/.config
	gunzip -f $(LINUX_CONFIG).gz
	gunzip -f $(CONFIG_CONFIG).gz
	$(MAKE) oldconfig
endif

.PHONY: oldconfig
oldconfig: Kconfig conf
	KCONFIG_NOTIMESTAMP=1 $(SCRIPTSDIR)/conf -o Kconfig
	@$(MAKE) oldconfig_linux
	@$(MAKE) oldconfig_modules
	@$(MAKE) oldconfig_config
	@$(MAKE) oldconfig_uClibc
	@chmod u+x config/setconfig
	@config/setconfig final

.PHONY: modules
modules:
	. $(LINUXDIR)/.config; if [ "$$CONFIG_MODULES" = "y" ]; then \
		[ -d $(LINUXDIR)/modules ] || mkdir $(LINUXDIR)/modules; \
		$(MAKEARCH_KERNEL) -C $(LINUXDIR) modules; \
	fi

.PHONY: modules_install
modules_install:
	. $(LINUX_CONFIG); \
	. $(CONFIG_CONFIG); \
	if [ "$$CONFIG_MODULES" = "y" ]; then \
		[ -d $(ROMFSDIR)/lib/modules ] || mkdir -p $(ROMFSDIR)/lib/modules; \
		rm -f $(ROMFSDIR)/lib/modules/modules.dep; \
		$(MAKEARCH_KERNEL) -C $(LINUXDIR) INSTALL_MOD_PATH=$(ROMFSDIR) DEPMOD=true modules_install; \
		rm -f $(ROMFSDIR)/lib/modules/*/build; \
		rm -f $(ROMFSDIR)/lib/modules/*/source; \
		find $(ROMFSDIR)/lib/modules -type f -name "*o" | xargs -r $(STRIP) -R .comment -R .note -g --strip-unneeded; \
		env NM=$(CROSS_COMPILE)nm $(ROOTDIR)/user/busybox/depmod.pl -P _ -b $(ROMFSDIR)/lib/modules/ -k $(ROOTDIR)/$(LINUXDIR)/vmlinux; \
		if [ "$$CONFIG_USER_BUSYBOX_FEATURE_MODPROBE_FANCY_ALIAS" = "y" ]; \
		then \
			find $(ROMFSDIR)/lib/modules -type f -name "*o" | \
			/bin/sh $(ROOTDIR)/tools/modules-alias.sh \
					$(ROMFSDIR)/etc/modprobe.conf;\
		fi; \
	fi

linux_%:
	KCONFIG_NOTIMESTAMP=1 $(MAKEARCH_KERNEL) -C $(LINUXDIR) $(patsubst linux_%,%,$@)
modules_%:
	[ ! -d modules ] || KCONFIG_NOTIMESTAMP=1 $(MAKEARCH) -C modules $(patsubst modules_%,%,$@)
config_%: vendors/Kconfig
	KCONFIG_NOTIMESTAMP=1 $(MAKEARCH) -C config $(patsubst config_%,%,$@)
oldconfig_config: config_oldconfig
oldconfig_modules: modules_oldconfig
oldconfig_linux: linux_oldconfig
oldconfig_uClibc:
	[ -z "$(findstring uClibc,$(LIBCDIR))" ] || KCONFIG_NOTIMESTAMP=1 $(MAKEARCH) -C $(LIBCDIR) oldconfig

############################################################################
#
# normal make targets
#

.PHONY: romfs
romfs: romfs.newlog romfs.subdirs modules_install romfs.post

.PHONY: romfs.newlog
romfs.newlog:
	rm -f $(IMAGEDIR)/romfs-inst.log

.PHONY: romfs.subdirs
romfs.subdirs:
	for dir in vendors $(DIRS) ; do [ ! -d $$dir ] || $(MAKEARCH) -C $$dir romfs || exit 1 ; done

.PHONY: romfs.post
romfs.post:
	$(MAKEARCH) -C vendors romfs.post
	-find $(ROMFSDIR)/. -name CVS | xargs -r rm -rf
	. $(LINUXDIR)/.config; if [ "$$CONFIG_INITRAMFS_SOURCE" != "" ]; then \
		$(MAKEARCH_KERNEL) -j$(HOST_NCPU) -C $(LINUXDIR) $(LINUXTARGET) || exit 1; \
	fi

.PHONY: image
image:
	[ -d $(IMAGEDIR) ] || mkdir $(IMAGEDIR)
	$(MAKEARCH) -C vendors image

.PHONY: release
release:
	$(MAKE) -C release release

.PHONY: single
single single%:
	$(MAKE) NON_SMP_BUILD=1 `expr $(@) : 'single[_]*\(.*\)'`

%_fullrelease:
	@echo "This target no longer works"
	@echo "Do a make -C release $@"
	exit 1
#
# fancy target that allows a vendor to have other top level
# make targets,  for example "make vendor_flash" will run the
# vendor_flash target in the vendors directory
#

vendor_%:
	$(MAKEARCH) -C vendors $@

.PHONY: linux
linux linux%_only:
	. $(LINUXDIR)/.config; if [ "$$CONFIG_INITRAMFS_SOURCE" != "" ]; then \
		mkdir -p `dirname $$CONFIG_INITRAMFS_SOURCE`; \
		touch $$CONFIG_INITRAMFS_SOURCE || exit 1; \
	fi
	@if expr "$(LINUXDIR)" : 'linux-2\.[0-4].*' > /dev/null && \
			 [ ! -f $(LINUXDIR)/.depend ] ; then \
		echo "ERROR: you need to do a 'make dep' first" ; \
		exit 1 ; \
	fi
	rm -f $(LINUXDIR)/usr/initramfs_data.cpio.gz
	$(MAKEARCH_KERNEL) -j$(HOST_NCPU) -C $(LINUXDIR) $(LINUXTARGET) || exit 1
	if [ -f $(LINUXDIR)/vmlinux ]; then \
		ln -f $(LINUXDIR)/vmlinux $(LINUXDIR)/linux ; \
	fi

.PHONY: sparse
sparse:
	$(MAKEARCH_KERNEL) -C $(LINUXDIR) C=1 $(LINUXTARGET) || exit 1

.PHONY: sparseall
sparseall:
	$(MAKEARCH_KERNEL) -C $(LINUXDIR) C=2 $(LINUXTARGET) || exit 1

.PHONY: subdirs
subdirs: linux modules
	for dir in $(DIRS) ; do [ ! -d $$dir ] || $(MAKEARCH) -C $$dir || exit 1 ; done

dep:
	@if [ ! -f $(LINUXDIR)/.config ] ; then \
		echo "ERROR: you need to do a 'make config' first" ; \
		exit 1 ; \
	fi
	$(MAKEARCH_KERNEL) -C $(LINUXDIR) dep

# This one removes all executables from the tree and forces their relinking
.PHONY: relink
relink:
	find user prop vendors -type f -name '*.gdb' | sed 's/^\(.*\)\.gdb/\1 \1.gdb/' | xargs rm -f

clean: modules_clean
	for dir in $(LINUXDIR) $(DIRS); do [ ! -d $$dir ] || $(MAKEARCH) -C $$dir clean ; done
	rm -rf $(ROMFSDIR)/*
	rm -rf $(STAGEDIR)/*
	rm -rf $(IMAGEDIR)/*
	rm -f $(LINUXDIR)/linux
	rm -f $(LINUXDIR)/include/asm
	rm -rf $(LINUXDIR)/net/ipsec/alg/libaes $(LINUXDIR)/net/ipsec/alg/perlasm
	find ./tools/ -maxdepth 1 -type l | xargs rm -f

real_clean mrproper: clean
	[ -d "$(LINUXDIR)" ] && $(MAKEARCH_KERNEL) -C $(LINUXDIR) mrproper || :
	-$(MAKEARCH) -C config clean
	[ -d uClibc ] && $(MAKEARCH) -C uClibc distclean || :
	[ -d "$(RELDIR)" ] && $(MAKEARCH) -C $(RELDIR) clean || :
	-$(MAKEARCH) -C config clean
	rm -rf romfs Kconfig config.arch images
	rm -rf .config .config.old .oldconfig autoconf.h auto.conf
	rm -rf staging

distclean: mrproper
	-$(MAKEARCH_KERNEL) -C $(LINUXDIR) distclean
	-rm -f user/tinylogin/applet_source_list user/tinylogin/config.h
	-rm -f lib/uClibc lib/glibc
	-$(MAKE) -C tools/ucfront clean
	-rm -f tools/ucfront-gcc tools/ucfront-g++ tools/ucfront-ld
	-$(MAKE) -C tools/sg-cksum clean
	-rm -f tools/cksum

.PHONY: bugreport
bugreport:
	rm -rf ./bugreport.tar.gz ./bugreport
	mkdir bugreport
	$(HOSTCC) -v 2> ./bugreport/host_vers
	$(CROSS_COMPILE)gcc -v 2> ./bugreport/toolchain_vers
	cp .config bugreport/
	mkdir bugreport/$(LINUXDIR)
	cp $(LINUXDIR)/.config bugreport/$(LINUXDIR)/
	if [ -f $(LIBCDIR)/.config ] ; then \
		set -e ; \
		mkdir bugreport/$(LIBCDIR) ; \
		cp $(LIBCDIR)/.config bugreport/$(LIBCDIR)/ ; \
	fi
	mkdir bugreport/config
	cp config/.config bugreport/config/
	tar czf bugreport.tar.gz bugreport
	rm -rf ./bugreport
	@printf "\nPlease attach the file 'bugreport.tar.gz' to a bug report at\n http://blackfin.uclinux.org/gf/project/uclinux-dist/tracker/?action=TrackerItemAdd&tracker_id=141\n\n"

%_only:
	@case "$(@)" in \
	*/*) d=`expr $(@) : '\([^/]*\)/.*'`; \
	     t=`expr $(@) : '[^/]*/\(.*\)'`; \
	     $(MAKEARCH) -C $$d $$t;; \
	*)   $(MAKEARCH) -C $(@:_only=);; \
	esac

%_clean:
	@case "$(@)" in \
	*/*) d=`expr $(@) : '\([^/]*\)/.*'`; \
	     t=`expr $(@) : '[^/]*/\(.*\)'`; \
	     $(MAKEARCH) -C $$d $$t;; \
	*)   $(MAKEARCH) -C $(@:_clean=) clean;; \
	esac

%_romfs:
	@case "$(@)" in \
	*/*) d=`expr $(@) : '\([^/]*\)/.*'`; \
	     t=`expr $(@) : '[^/]*/\(.*\)'`; \
	     $(MAKEARCH) -C $$d $$t;; \
	*)   $(MAKEARCH) -C $(@:_romfs=) romfs;; \
	esac

%_defconfig: Kconfig conf
	@if [ ! -f "vendors/$(@:_defconfig=)/config.device" ]; then \
		echo "vendors/$(@:_defconfig=)/config.device must exist first"; \
		exit 1; \
	 fi
	-$(MAKE) clean > /dev/null 2>&1
	cp vendors/$(@:_defconfig=)/config.device .config
	chmod u+x config/setconfig
	yes "" | config/setconfig defaults
	config/setconfig final
	#$(MAKE) dep
%_default: Kconfig conf
	$(MAKE) $(@:_default=_defconfig)
	$(MAKE)

config_error:
	@echo "*************************************************"
	@echo "You have not run make config."
	@echo "The build sequence for this source tree is:"
	@echo "1. 'make config' or 'make xconfig'"
	@echo "2. 'make dep'"
	@echo "3. 'make'"
	@echo "*************************************************"
	@exit 1

prune: ucfront
	@for i in `ls -d linux-* | grep -v $(LINUXDIR)`; do \
		rm -fr $$i; \
	done
	$(MAKE) -C lib prune
	$(MAKE) -C user prune
	$(MAKE) -C vendors prune

dist-prep:
	-find $(ROOTDIR) -name 'Makefile*.bin' | while read t; do \
		$(MAKEARCH) -C `dirname $$t` -f `basename $$t` $@; \
	 done

help:
	@echo "Quick reference for various supported make commands."
	@echo "----------------------------------------------------"
	@echo ""
	@echo "make xconfig               Configure the target etc"
	@echo "make config                \""
	@echo "make menuconfig            \""
	@echo "make qconfig               \""
	@echo "make gconfig               \""
	@echo "make dep                   2.4 and earlier kernels need this step"
	@echo "make                       build the entire tree and final images"
	@echo "make clean                 clean out compiled files, but not config"
	@echo "make distclean             clean out all non-distributed files"
	@echo "make oldconfig             re-run the config without interaction"
	@echo "make linux                 compile the selected kernel only"
	@echo "make romfs                 install all files to romfs directory"
	@echo "make image                 combine romfs and kernel into final image"
	@echo "make modules               build all modules"
	@echo "make modules_install       install modules into romfs"
	@echo "make DIR_only              build just the directory DIR"
	@echo "make DIR_romfs             install files from directory DIR to romfs"
	@echo "make DIR_clean             clean just the directory DIR"
	@echo "make single                non-parallelised build"
	@echo "make single[make-target]   non-parallelised build of \"make-target\""
	@echo "make V/P_default           full default build for V=Vendor/P=Product"
	@echo "make remoteconfig IP=bar   grab the (kernel & userspace) config files from remote target
	@echo "make prune                 clean out uncompiled source (be careful)"
	@echo ""
	@echo "Typically you want to start with this sequence before experimenting."
	@echo ""
	@echo "make config                select platform, kernel, etc, customise nothing."
	@echo "make dep                   optional but safe even on newer kernels."
	@echo "make                       build it as the creators intended."
	@exit 0
	

############################################################################
