############################################################################

#
# Makefile -- Top level uClinux makefile.
#
# Copyright (c) 2001-2004, SnapGear (www.snapgear.com)
# Copyright (c) 2001,  Lineo
#

VERSIONPKG = 3.1.0
VERSIONSTR = $(CONFIG_VENDOR)/$(CONFIG_PRODUCT) Version $(VERSIONPKG)

############################################################################
#
# Lets work out what the user wants, and if they have configured us yet
#

ifeq (.config,$(wildcard .config))
include .config

all: subdirs romfs modules modules_install image
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
PATH	 := $(PATH):$(ROOTDIR)/tools
HOSTCC   = cc
IMAGEDIR = $(ROOTDIR)/images
RELDIR   = $(ROOTDIR)/release
ROMFSDIR = $(ROOTDIR)/romfs
ROMFSINST= romfs-inst.sh
SCRIPTSDIR = $(ROOTDIR)/config/scripts
TFTPDIR    = /tftpboot


LINUX_CONFIG  = $(ROOTDIR)/$(LINUXDIR)/.config
CONFIG_CONFIG = $(ROOTDIR)/config/.config
MODULES_CONFIG = $(ROOTDIR)/modules/.config


CONFIG_SHELL := $(shell if [ -x "$$BASH" ]; then echo $$BASH; \
	  else if [ -x /bin/bash ]; then echo /bin/bash; \
	  else echo sh; fi ; fi)

ifeq (config.arch,$(wildcard config.arch))
include config.arch
ARCH_CONFIG = $(ROOTDIR)/config.arch
export ARCH_CONFIG
endif

ifneq ($(SUBARCH),)
# Using UML, so make the kernel and non-kernel with different ARCHs
MAKEARCH = $(MAKE) ARCH=$(SUBARCH) CROSS_COMPILE=$(CROSS_COMPILE)
MAKEARCH_KERNEL = $(MAKE) ARCH=$(ARCH) SUBARCH=$(SUBARCH) CROSS_COMPILE=$(CROSS_COMPILE)
else
MAKEARCH = $(MAKE) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE)
MAKEARCH_KERNEL = $(MAKEARCH)
endif

DIRS    = $(VENDOR_TOPDIRS) lib user
VENDDIR = $(ROOTDIR)/vendors/$(CONFIG_VENDOR)/$(CONFIG_PRODUCT)/.

export VENDOR PRODUCT ROOTDIR LINUXDIR HOSTCC CONFIG_SHELL
export CONFIG_CONFIG LINUX_CONFIG ROMFSDIR SCRIPTSDIR
export VERSIONPKG VERSIONSTR ROMFSINST PATH IMAGEDIR RELDIR RELFILES TFTPDIR

############################################################################

#
# Config stuff,  we recall ourselves to load the new config.arch before
# running the kernel and other config scripts
#

.PHONY: config.tk config.in

config.in:
	config/mkconfig > config.in

config.tk: config.in
	$(MAKE) -C $(SCRIPTSDIR) tkparse
	ARCH=dummy $(SCRIPTSDIR)/tkparse < config.in > config.tmp
	@if [ -f /usr/local/bin/wish ];	then \
		echo '#!'"/usr/local/bin/wish -f" > config.tk; \
	else \
		echo '#!'"/usr/bin/wish -f" > config.tk; \
	fi
	cat $(SCRIPTSDIR)/header.tk >> ./config.tk
	cat config.tmp >> config.tk
	rm -f config.tmp
	echo "set defaults \"/dev/null\"" >> config.tk
	echo "set help_file \"config/Configure.help\"" >> config.tk
	cat $(SCRIPTSDIR)/tail.tk >> config.tk
	chmod 755 config.tk

.PHONY: xconfig
xconfig: config.tk
	@wish -f config.tk
	@if [ ! -f .config ]; then \
		echo; \
		echo "You have not saved your config, please re-run make config"; \
		echo; \
		exit 1; \
	 fi
	@config/setconfig defaults
	@if egrep "^CONFIG_DEFAULTS_KERNEL=y" .config > /dev/null; then \
		$(MAKE) linux_xconfig; \
	 fi
	@if egrep "^CONFIG_DEFAULTS_MODULES=y" .config > /dev/null; then \
		$(MAKE) modules_xconfig; \
	 fi
	@if egrep "^CONFIG_DEFAULTS_VENDOR=y" .config > /dev/null; then \
		$(MAKE) config_xconfig; \
	 fi
	@config/setconfig final

.PHONY: config
config: config.in
	@HELP_FILE=config/Configure.help \
		$(CONFIG_SHELL) $(SCRIPTSDIR)/Configure config.in
	@config/setconfig defaults
	@if egrep "^CONFIG_DEFAULTS_KERNEL=y" .config > /dev/null; then \
		$(MAKE) linux_config; \
	 fi
	@if egrep "^CONFIG_DEFAULTS_MODULES=y" .config > /dev/null; then \
		$(MAKE) modules_config; \
	 fi
	@if egrep "^CONFIG_DEFAULTS_VENDOR=y" .config > /dev/null; then \
		$(MAKE) config_config; \
	 fi
	@config/setconfig final

.PHONY: menuconfig
menuconfig: config.in
	$(MAKE) -C $(SCRIPTSDIR)/lxdialog all
	@HELP_FILE=config/Configure.help \
		$(CONFIG_SHELL) $(SCRIPTSDIR)/Menuconfig config.in
	@if [ ! -f .config ]; then \
		echo; \
		echo "You have not saved your config, please re-run make config"; \
		echo; \
		exit 1; \
	 fi
	@config/setconfig defaults
	@if egrep "^CONFIG_DEFAULTS_KERNEL=y" .config > /dev/null; then \
		$(MAKE) linux_menuconfig; \
	 fi
	@if egrep "^CONFIG_DEFAULTS_MODULES=y" .config > /dev/null; then \
		$(MAKE) modules_menuconfig; \
	 fi
	@if egrep "^CONFIG_DEFAULTS_VENDOR=y" .config > /dev/null; then \
		$(MAKE) config_menuconfig; \
	 fi
	@config/setconfig final

.PHONY: oldconfig
oldconfig:
	@$(MAKE) oldconfig_linux
	@$(MAKE) oldconfig_modules
	@$(MAKE) oldconfig_config
#	@$(MAKE) oldconfig_uClibc
	@config/setconfig final

.PHONY: modules
modules:
	. $(LINUXDIR)/.config; if [ "$$CONFIG_MODULES" = "y" ]; then \
		[ -d $(LINUXDIR)/modules ] || mkdir $(LINUXDIR)/modules; \
		$(MAKEARCH_KERNEL) -C $(LINUXDIR) modules; \
	fi

.PHONY: modules_install
modules_install:
	. $(LINUXDIR)/.config; if [ "$$CONFIG_MODULES" = "y" ]; then \
		[ -d $(ROMFSDIR)/lib/modules ] || mkdir -p $(ROMFSDIR)/lib/modules; \
		rm -f $(ROMFSDIR)/lib/modules/modules.dep; \
		$(MAKEARCH_KERNEL) -C $(LINUXDIR) INSTALL_MOD_PATH=$(ROMFSDIR) DEPMOD=true modules_install; \
		rm -f $(ROMFSDIR)/lib/modules/*/build; \
		find $(ROMFSDIR)/lib/modules -type f | xargs -r $(STRIP) -g; \
		$(ROOTDIR)/user/busybox/examples/depmod.pl -b $(ROMFSDIR)/lib/modules/ -k $(ROOTDIR)/$(LINUXDIR)/vmlinux; \
	fi

linux_xconfig:
	$(MAKEARCH_KERNEL) -C $(LINUXDIR) xconfig
linux_menuconfig:
	$(MAKEARCH_KERNEL) -C $(LINUXDIR) menuconfig
linux_config:
	$(MAKEARCH_KERNEL) -C $(LINUXDIR) config
modules_xconfig:
	[ ! -d modules ] || $(MAKEARCH) -C modules xconfig
modules_menuconfig:
	[ ! -d modules ] || $(MAKEARCH) -C modules menuconfig
modules_config:
	[ ! -d modules ] || $(MAKEARCH) -C modules config
modules_clean:
	-[ ! -d modules ] || $(MAKEARCH) -C modules clean
config_xconfig:
	$(MAKEARCH) -C config xconfig
config_menuconfig:
	$(MAKEARCH) -C config menuconfig
config_config:
	$(MAKEARCH) -C config config
oldconfig_config:
	$(MAKEARCH) -C config oldconfig
oldconfig_modules:
	[ ! -d modules ] || $(MAKEARCH) -C modules oldconfig
oldconfig_linux:
	$(MAKEARCH_KERNEL) -C $(LINUXDIR) oldconfig
oldconfig_uClibc:
	[ -z "$(findstring uClibc,$(LIBCDIR))" ] || $(MAKEARCH) -C $(LIBCDIR) oldconfig

############################################################################
#
# normal make targets
#

.PHONY: romfs
romfs:
	[ -e $(ROMFSDIR) ] || mkdir $(ROMFSDIR)
	for dir in $(VENDDIR) $(DIRS) ; do [ ! -d $$dir ] || $(MAKEARCH) -C $$dir romfs || exit 1 ; done
	-find $(ROMFSDIR)/. -name CVS | xargs -r rm -rf
	if egrep "^CONFIG_INSTALL_ELF_SHARED_LIBS=y" $(CONFIG_CONFIG) > /dev/null; then \
		t=`$(CC) -print-file-name=libc.a`; \
		t=`dirname $$t`/../runtime; \
		for i in $$t/lib/*so*; do \
			bn=`basename $$i`; \
			if [ -f $$i -a ! -h $$i -a $$bn != "lib1.so" -a $$bn != "lib2.so" ] ; then \
				$(ROMFSINST) -p 755 $$i /lib/$$bn; \
			fi; \
		done; \
		for i in $$t/lib/*so*; do \
			if [ -h $$i -a -e $$i ] ; then \
				j=`readlink $$i`; \
				$(ROMFSINST) -s \
					/lib/`basename $$j` \
					/lib/`basename $$i`; \
			fi; \
		done; \
		if [ -x $$t/lib/ld-uClibc-$(UCLIBC_VERSION).so ] ; then \
			$(ROMFSINST) -s \
				/lib/ld-uClibc-$(UCLIBC_VERSION).so \
				/lib/ld-linux.so.2; \
		fi; \
		t=`$(CC) -mfdpic -print-file-name=libstc++.so`; \
		t=`dirname $$t`; \
		for i in $$t/libstdc++.so*; do \
			if [ -f $$i -a ! -h $$i ] ; then \
				$(ROMFSINST) -p 755 $$i /lib/`basename $$i`; \
			fi; \
		done; \
		for i in $$t/libstdc++.so*; do \
			if [ -h $$i -a -e $$i ] ; then \
				j=`readlink $$i`; \
				$(ROMFSINST) -s \
					/lib/`basename $$j` \
					/lib/`basename $$i`; \
			fi; \
		done; \
		t=`$(CC) -mfdpic -print-file-name=libgcc_s_mfdpic.so`; \
		t=`dirname $$t`; \
		if [ $$t = "." ] ; then \
			t=`$(CC) -mfdpic -print-file-name=libgcc_s.so`; \
			t=`dirname $$t`; \
			for i in $$t/libgcc_s.so*; do \
				if [ -f $$i -a ! -h $$i ] ; then \
					$(ROMFSINST) -p 755 $$i /lib/`basename $$i`; \
				fi; \
			done; \
			for i in $$t/libgcc_s.so*; do \
				if [ -h $$i -a -e $$i ] ; then \
					j=`readlink $$i`; \
					$(ROMFSINST) -s \
						/lib/`basename $$j` \
						/lib/`basename $$i`; \
				fi; \
			done; \
		else \
			for i in $$t/libgcc_s_mfdpic.so*; do \
				if [ -f $$i -a ! -h $$i ] ; then \
					$(ROMFSINST) -p 755 $$i /lib/`basename $$i`; \
				fi; \
			done; \
			for i in $$t/libgcc_s_mfdpic.so*; do \
				if [ -h $$i -a -e $$i ] ; then \
					j=`readlink $$i`; \
					$(ROMFSINST) -s \
						/lib/`basename $$j` \
						/lib/`basename $$i`; \
				fi; \
			done; \
		fi; \
	fi
	if egrep "^CONFIG_INSTALL_FLAT_SHARED_LIBS=y" $(CONFIG_CONFIG) > /dev/null; then \
		t=`$(CC) -print-file-name=libc.a`; \
		t=`dirname $$t`/../runtime; \
		for i in $$t/lib/lib?.so; do \
			bn=`basename $$i`; \
			if [ -f $$i -a ! -h $$i ] ; then \
				$(ROMFSINST) -p 755 $$i /lib/$$bn; \
			fi; \
		done; \
	fi

.PHONY: image
image:
	[ -d $(IMAGEDIR) ] || mkdir $(IMAGEDIR)
	$(MAKEARCH) -C $(VENDDIR) image

.PHONY: netflash
netflash netflash_only:
	make -C prop/mstools CONFIG_PROP_MSTOOLS_NETFLASH_NETFLASH=y

.PHONY: release
release:
	make -C release release

%_fullrelease:
	make -C release $@
#
# fancy target that allows a vendor to have other top level
# make targets,  for example "make vendor_flash" will run the
# vendor_flash target in the vendors directory
#

vendor_%:
	$(MAKEARCH) -C $(VENDDIR) $@

.PHONY: linux
linux linux%_only:
	@if [ $(LINUXDIR) != linux-2.5.x -a $(LINUXDIR) != linux-2.6.x -a ! -f $(LINUXDIR)/.depend ] ; then \
		echo "ERROR: you need to do a 'make dep' first" ; \
		exit 1 ; \
	fi
	$(MAKEARCH_KERNEL) -C $(LINUXDIR) $(LINUXTARGET) || exit 1
	if [ -f $(LINUXDIR)/vmlinux ]; then \
		ln -f $(LINUXDIR)/vmlinux $(LINUXDIR)/linux ; \
	fi

.PHONY: subdirs
subdirs: linux
	for dir in $(DIRS) ; do [ ! -d $$dir ] || $(MAKEARCH_KERNEL) -C $$dir || exit 1 ; done

dep:
	@if [ ! -f $(LINUXDIR)/.config ] ; then \
		echo "ERROR: you need to do a 'make config' first" ; \
		exit 1 ; \
	fi
	$(MAKEARCH_KERNEL) -C $(LINUXDIR) dep

# This one removes all executables from the tree and forces their relinking
.PHONY: relink
relink:
	find user -type f -name '*.gdb' | sed 's/^\(.*\)\.gdb/\1 \1.gdb/' | xargs rm -f
	find prop -type f -name '*.gdb' | sed 's/^\(.*\)\.gdb/\1 \1.gdb/' | xargs rm -f
	find $(VENDDIR) -type f -name '*.gdb' | sed 's/^\(.*\)\.gdb/\1 \1.gdb/' | xargs rm -f

clean: modules_clean
	for dir in $(LINUXDIR) $(DIRS) $(VENDDIR) ; do [ ! -d $$dir ] || $(MAKEARCH) -C $$dir clean ; done
	rm -rf $(ROMFSDIR)/*
	rm -rf $(IMAGEDIR)/*
	rm -f config.tk
	rm -f $(LINUXDIR)/linux
	rm -rf $(LINUXDIR)/net/ipsec/alg/libaes $(LINUXDIR)/net/ipsec/alg/perlasm

real_clean mrproper: clean
	-$(MAKEARCH_KERNEL) -C $(LINUXDIR) mrproper
	-$(MAKEARCH) -C config clean
	-$(MAKEARCH) -C uClibc distclean
	-$(MAKEARCH) -C $(RELDIR) clean
	rm -rf romfs config.in config.arch config.tk images
	rm -f modules/config.tk
	rm -rf .config .config.old .oldconfig autoconf.h

distclean: mrproper
	-$(MAKEARCH_KERNEL) -C $(LINUXDIR) distclean
	-rm -f user/tinylogin/applet_source_list user/tinylogin/config.h

%_only:
	[ ! -d "$(@:_only=)" ] || $(MAKEARCH) -C $(@:_only=)

%_clean:
	[ ! -d "$(@:_clean=)" ] || $(MAKEARCH) -C $(@:_clean=) clean

%_config:
	@if [ ! -f "vendors/$(@:_config=)/config.device" ]; then \
		echo "vendors/$(@:_config=)/config.device must exist first"; \
		exit 1; \
	fi
#	make distclean > /dev/null 2>&1
	cp vendors/$(@:_config=)/config.device .config
	cp vendors/$(@:_config=)/config.uClibc uClibc/.config
	cp vendors/$(@:_config=)/config.vendor-2.6.x config/.config
	cp vendors/$(@:_config=)/config.linux-2.6.x linux-2.6.x/.config
	ln -sf vendors/$(@:_config=)/config.arch .
	yes "" | make oldconfig

%_default:
	@if [ ! -f "vendors/$(@:_default=)/config.device" ]; then \
		echo "vendors/$(@:_default=)/config.device must exist first"; \
		exit 1; \
	fi
#	make distclean > /dev/null 2>&1
	cp vendors/$(@:_default=)/config.device .config
	cp vendors/$(@:_default=)/config.uClibc uClibc/.config
	cp vendors/$(@:_default=)/config.vendor-2.6.x config/.config
	cp vendors/$(@:_default=)/config.linux-2.6.x linux-2.6.x/.config
	ln -s vendors/$(@:_default=)/config.arch .
	yes "" | make oldconfig
	make

config_error:
	@echo "*************************************************"
	@echo "You have not run make config."
	@echo "The build sequence for this source tree is:"
	@echo "1. 'make config' or 'make xconfig'"
	@echo "2. 'make dep'"
	@echo "3. 'make'"
	@echo "*************************************************"
	@exit 1

prune:
	$(MAKE) -C user prune

dist-prep:
	-find $(ROOTDIR) -name 'Makefile*.bin' | while read t; do \
		$(MAKEARCH) -C `dirname $$t` -f `basename $$t` $@; \
	 done

############################################################################
