# Makefile for pcmciautils
#
# Copyright (C) 2005      Dominik Brodowski <linux@dominikbrodowski.net>
#
# Based largely on the Makefile for udev by:
#
# Copyright (C) 2003,2004 Greg Kroah-Hartman <greg@kroah.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; version 2 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
#

# Set this to 'false' if you do not need the socket-startup script
# 
# You don't need it if the socket driver does not select
# PCCARD_NONSTATIC -- that is the case for many embedded systems --
# and for yenta_socket if the cardbus bridge is either below a
# PCI-PCI bridge, or where the PCI bus is not equivalent to the host
# bus (e.g. on PPC)
STARTUP = true

# Set this to true if you want to use 'udev' instead of 'hotplug'
# to invoke the necessary pcmciautils commands.
UDEV = true

# Set the following to `true' to log the debug
# and make a unstripped, unoptimized  binary.
# Leave this set to `false' for production use.
DEBUG = false

# Set this to true if you want to statically link the binaries
# to be compiled.
STATIC = false

# make the build silent. Set this to something else to make it noisy again.
V = false


PCCARDCTL =			pccardctl
LSPCMCIA =			lspcmcia
PCMCIA_CHECK_BROKEN_CIS =	pcmcia-check-broken-cis
PCMCIA_SOCKET_STARTUP =		pcmcia-socket-startup
CBDUMP =			cbdump
CISDUMP =			dump_cis

VERSION =	015
#INSTALL_DIR =	/usr/local/sbin
RELEASE_NAME =	pcmciautils-$(VERSION)

#DESTDIR =

KERNEL_DIR = /lib/modules/${shell uname -r}/build

# override this to make udev look in a different location for it's config files
prefix =
exec_prefix =	${prefix}
etcdir =	${prefix}/etc
sbindir =	${exec_prefix}/sbin
mandir =	${prefix}/usr/share/man
srcdir = .

INSTALL = /usr/bin/install -c
INSTALL_PROGRAM = ${INSTALL}
INSTALL_DATA  = ${INSTALL} -m 644
INSTALL_SCRIPT = ${INSTALL_PROGRAM}
SYMLINK = ln -sf

# place to put our hotplug scripts nodes
hotplugdir =	${etcdir}/hotplug

# place to put our udev rules to
udevrulesdir = 	${etcdir}/udev/rules.d

# place where PCMICIA config is put to
pcmciaconfdir =	${etcdir}/pcmcia

# set up PWD so that older versions of make will work with our build.
PWD = $(shell pwd)

# If you are running a cross compiler, you may want to set this
# to something more interesting, like "arm-linux-".  If you want
# to compile vs uClibc, that can be done here as well.
CROSS = #/usr/i386-linux-uclibc/usr/bin/i386-uclibc-
CC = $(CROSS)gcc
LD = $(CROSS)gcc
AR = $(CROSS)ar
STRIP = $(CROSS)strip
RANLIB = $(CROSS)ranlib
HOSTCC = gcc

export CROSS CC AR STRIP RANLIB CFLAGS LDFLAGS LIB_OBJS ARCH_LIB_OBJS CRT0

# code taken from uClibc to determine the current arch
ARCH := ${shell $(CC) -dumpmachine | sed -e s'/-.*//' -e 's/i.86/i386/' -e 's/sparc.*/sparc/' \
	-e 's/arm.*/arm/g' -e 's/m68k.*/m68k/' -e 's/powerpc/ppc/g'}

# code taken from uClibc to determine the gcc include dir
GCCINCDIR := ${shell LC_ALL=C $(CC) -print-search-dirs | sed -ne "s/install: \(.*\)/\1include/gp"}

# code taken from uClibc to determine the libgcc.a filename
GCC_LIB := $(shell $(CC) -print-libgcc-file-name )

# use '-Os' optimization if available, else use -O2
OPTIMIZATION := ${shell if $(CC) -Os -S -o /dev/null -xc /dev/null >/dev/null 2>&1; \
		then echo "-Os"; else echo "-O2" ; fi}

# check if compiler option is supported
cc-supports = ${shell if $(CC) ${1} -S -o /dev/null -xc /dev/null > /dev/null 2>&1; then echo "$(1)"; fi;}

WARNINGS := -Wall -Wchar-subscripts -Wpointer-arith -Wsign-compare
WARNINGS += $(call cc-supports,-Wno-pointer-sign)
WARNINGS += $(call cc-supports,-Wdeclaration-after-statement)
WARNINGS += -Wshadow

CFLAGS := -pipe -DPCMCIAUTILS_VERSION=\"$(VERSION)\"
YFLAGS := -d

HEADERS = \
	src/cistpl.h	\
	src/startup.h	\
	src/yacc_config.h 


OBJS = \
	src/lex_config.l		\
	src/pccardctl.c			\
	src/pcmcia-check-broken-cis.c	\
	src/read-cis.c			\
	src/startup.c			\
	src/startup.h			\
	src/yacc_config.h		\
	src/yacc_config.y

CFLAGS +=	-I$(PWD)/src

CFLAGS += $(WARNINGS) -I$(GCCINCDIR)

LIB_OBJS = -lc -lsysfs
LIB_PCI_OBJS = -lc -lpci

ifeq ($(strip $(STATIC)),true)
	LIB_OBJS = -lsysfs
	LIB_PCI_OBJS = -lpci
	LDFLAGS += -static
else
	LDFLAGS += -Wl,-warn-common
endif

ifeq ($(strip $(V)),false)
	QUIET=@$(PWD)/build/ccdv
	HOST_PROGS=build/ccdv
else
	QUIET=
	HOST_PROGS=
endif

# if DEBUG is enabled, then we do not strip or optimize
ifeq ($(strip $(DEBUG)),true)
	CFLAGS  += -O1 -g -DDEBUG -D_GNU_SOURCE
	STRIPCMD = /bin/true -Since_we_are_debugging
else
	CFLAGS  += $(OPTIMIZATION) -fomit-frame-pointer -D_GNU_SOURCE
	STRIPCMD = $(STRIP) -s --remove-section=.note --remove-section=.comment
endif

# HOTPLUG or UDEV?
ifeq ($(strip $(UDEV)),false)
	INSTALL_TARGETS = install-hotplug
	UNINSTALL_TARGETS = uninstall-hotplug
else
	INSTALL_TARGETS = install-udev
	UNINSTALL_TARGETS = uninstall-udev
endif



# if STARTUP is disabled, we can skip a few things
ifeq ($(strip $(STARTUP)),false)
	PCMCIA_SOCKET_STARTUP_BUILD =
else
	PCMCIA_SOCKET_STARTUP_BUILD = $(PCMCIA_SOCKET_STARTUP)
	INSTALL_TARGETS += install-config install-socket-tools
	UNINSTALL_TARGETS += uninstall-socket-tools
	ifeq ($(strip $(UDEV)),false)
		INSTALL_TARGETS += install-socket-hotplug
		UNINSTALL_TARGETS += uninstall-socket-hotplug
	endif
endif

#udev rules collection
UDEV_RULES_FILE = udev/60-pcmcia.rules
UDEV_RULES = udev/rules-start udev/rules-modprobe udev/rules-base
ifneq ($(strip $(STARTUP)),false)
	UDEV_RULES += udev/rules-nonstaticsocket
endif
UDEV_RULES += udev/rules-end


all: ccdv $(PCCARDCTL) $(PCMCIA_CHECK_BROKEN_CIS) $(PCMCIA_SOCKET_STARTUP_BUILD) udevrules

ccdv:
	@echo "Building ccdv"
	@$(HOSTCC) -O1 build/ccdv.c -o build/ccdv

.c.o:
	$(QUIET) $(CC) $(CFLAGS) -c -o $@ $<

%.c %.h : %.y
	$(YACC) $(YFLAGS) $<
	mv y.tab.c $*.c
	mv y.tab.h $*.h

$(PCCARDCTL): $(LIBC) src/$(PCCARDCTL).o src/$(PCCARDCTL).c $(OBJS) $(HEADERS)
	$(QUIET) $(LD) $(LDFLAGS) -o $@ $(CRT0) src/$(PCCARDCTL).o $(LIB_OBJS) $(ARCH_LIB_OBJS)
	$(QUIET) $(STRIPCMD) $@

$(PCMCIA_CHECK_BROKEN_CIS): $(LIBC) src/$(PCMCIA_CHECK_BROKEN_CIS).o src/read-cis.o $(OBJS) $(HEADERS)
	$(QUIET) $(LD) $(LDFLAGS) -o $@ $(CRT0) src/$(PCMCIA_CHECK_BROKEN_CIS).o src/read-cis.o $(LIB_OBJS) $(ARCH_LIB_OBJS)
	$(QUIET) $(STRIPCMD) $@

$(PCMCIA_SOCKET_STARTUP): $(LIBC) src/startup.o src/yacc_config.o src/lex_config.o $(OBJS) $(HEADERS)
	$(QUIET) $(LD) $(LDFLAGS) -o $@ $(CRT0) src/startup.o src/yacc_config.o src/lex_config.o $(LIB_OBJS) $(ARCH_LIB_OBJS)
	$(QUIET) $(STRIPCMD) $@

yacc_config.o lex_config.o: %.o: %.c
	$(CC) -c -MD -O -pipe $(CPPFLAGS) $<

debugtools: ccdv $(CBDUMP) $(CISDUMP)

$(CBDUMP): $(LIBC) debug/cbdump.o
	$(QUIET) $(LD) $(LDFLAGS) -o $@ $(CRT0) debug/$(CBDUMP).o $(LIB_PCI_OBJS) $(ARCH_LIB_OBJS)
	$(QUIET) $(STRIPCMD) $@

$(CISDUMP): $(LIBC) src/read-cis.o debug/parse_cis.o debug/dump_cis.o
	$(QUIET) $(LD) $(LDFLAGS) -o $@ $(CRT0) debug/$(CISDUMP).o src/read-cis.o debug/parse_cis.o $(LIB_OBJS) $(ARCH_LIB_OBJS)
	$(QUIET) $(STRIPCMD) $@

udevrules:
	cat $(UDEV_RULES) > $(UDEV_RULES_FILE)

clean:
	-find . \( -not -type d \) -and \( -name '*~' -o -name '*.[oas]' \) -type f -print \
	 | xargs rm -f 
	-rm -f $(PCCARDCTL) $(PCMCIA_CHECK_BROKEN_CIS) $(PCMCIA_SOCKET_STARTUP)
	-rm -f $(CBDUMP) $(CISDUMP)
	-rm -f src/yacc_config.c src/yacc_config.d src/lex_config.c src/lex_config.d src/yacc_config.h
	-rm -f udev/60-pcmcia.rules
	-rm -f build/ccdv

install-hotplug:
	$(INSTALL) -d $(DESTDIR)$(hotplugdir)
	$(INSTALL_PROGRAM) -D hotplug/pcmcia.agent $(DESTDIR)$(hotplugdir)/pcmcia.agent
	$(INSTALL_PROGRAM) -D hotplug/pcmcia.rc $(DESTDIR)$(hotplugdir)/pcmcia.rc

uninstall-hotplug:
	- rm -f $(DESTDIR)$(hotplugdir)/pcmcia.agent $(DESTDIR)$(hotplugdir)/pcmcia.rc

install-socket-hotplug:
	$(INSTALL_PROGRAM) -D hotplug/pcmcia_socket.agent $(DESTDIR)$(hotplugdir)/pcmcia_socket.agent
	$(INSTALL_PROGRAM) -D hotplug/pcmcia_socket.rc $(DESTDIR)$(hotplugdir)/pcmcia_socket.rc

uninstall-socket-hotplug:
	- rm -f $(DESTDIR)$(hotplugdir)/pcmcia_socket.agent $(DESTDIR)$(hotplugdir)/pcmcia_socket.rc
install-socket-tools:
	$(INSTALL_PROGRAM) -D $(PCMCIA_SOCKET_STARTUP) $(DESTDIR)$(sbindir)/$(PCMCIA_SOCKET_STARTUP)

uninstall-socket-tools:
	- rm -f $(DESTDIR)$(sbindir)/$(PCMCIA_SOCKET_STARTUP)

install-tools:
	$(INSTALL) -d $(DESTDIR)$(sbindir)
	$(INSTALL_PROGRAM) -D $(PCCARDCTL) $(DESTDIR)$(sbindir)/$(PCCARDCTL)
	$(INSTALL_PROGRAM) -D $(PCMCIA_CHECK_BROKEN_CIS) $(DESTDIR)$(sbindir)/$(PCMCIA_CHECK_BROKEN_CIS)
	$(SYMLINK) $(PCCARDCTL) $(DESTDIR)$(sbindir)/$(LSPCMCIA)

uninstall-tools:
	- rm -f $(DESTDIR)$(sbindir)/$(PCCARDCTL)
	- rm -f $(DESTDIR)$(sbindir)/$(PCMCIA_CHECK_BROKEN_CIS)
	- rm -f $(DESTDIR)$(sbindir)/$(LSPCMCIA)

install-config:
	$(INSTALL) -d $(DESTDIR)$(pcmciaconfdir)
	$(INSTALL_DATA)  -D config/config.opts $(DESTDIR)$(pcmciaconfdir)/config.opts

uninstall-config:
#	- rm -f $(DESTDIR)$(pcmciaconfdir)/config.opts

install-udev:
	$(INSTALL_DATA) -D $(UDEV_RULES_FILE) $(DESTDIR)$(udevrulesdir)/60-pcmcia.rules

uninstall-udev:
	- rm -f $(DESTDIR)$(udevrulesdir)/60-pcmcia.rules

install-man:
	$(INSTALL_DATA) -D man/man8/pccardctl.8 $(DESTDIR)$(mandir)/man8/pccardctl.8
	$(SYMLINK) pccardctl.8 $(DESTDIR)$(mandir)/man8/lspcmcia.8

uninstall-man:
	- rm $(DESTDIR)$(mandir)/man8/pccardctl.8
	- rm $(DESTDIR)$(mandir)/man8/lspcmcia.8


install: install-tools install-man $(INSTALL_TARGETS)

uninstall: uninstall-tools uninstall-man $(UNINSTALL_TARGETS)
