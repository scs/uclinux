# Makefile for tinylogin
#
# Copyright (C) 1999-2003 Erik Andersen <andersee@debian.org>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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

PROG      := tinylogin
VERSION   := 1.4
BUILDTIME := $(shell TZ=UTC date -u "+%Y.%m.%d-%H:%M%z")
export VERSION

# With a modern GNU make(1) (highly recommended, that's what all the
# developers use), all of the following configuration values can be
# overridden at the command line.  For example:
#   make CROSS=powerpc-linux- PREFIX=/mnt/app

# If you want to add some simple compiler switches (like -march=i686),
# especially from the command line, use this instead of CFLAGS directly.
# For optimization overrides, it's better still to set OPTIMIZATION.
CFLAGS_EXTRA =
 
# If you want a static binary, turn this on.
DOSTATIC = false

# Set the following to `true' to make a debuggable build.
# Leave this set to `false' for production use.
DODEBUG = false

# Setting this to `true' will cause tinylogin to directly use the system's
# password and group functions. Assuming you use GNU libc, when this is
# `true', you will need to install the /etc/nsswitch.conf configuration file
# and the required libnss_* libraries. This generally makes your embedded
# system quite a bit larger... If you leave this off, tinylogin will directly 
# use the /etc/password, /etc/group files (and your system will be smaller, 
# and I will get fewer emails asking about how glibc NSS works). Enabling 
# this adds just 1.4k to the binary size (which is a _lot_ less then glibc NSS 
# costs). Note that if you want hostname resolution to work with glibc, you 
# still need the libnss_* libraries.
USE_SYSTEM_PWD_GRP = false

# Setting this to `true' will cause tinylogin to directly use the system's
# shadow password functions.  If you leave this off, tinylogin will use its 
# own (probably smaller) shadow password functions.
USE_SYSTEM_SHADOW = false

# This enables compiling with dmalloc ( http://dmalloc.com/ )
# which is an excellent public domain mem leak and malloc problem
# detector.  To enable dmalloc, before running tinylogin you will
# want to first set up your environment.
# eg: `export DMALLOC_OPTIONS=debug=0x14f47d83,inter=100,log=logfile`
# Do not enable this for production builds...
DODMALLOC = false

# Electric-fence is another very useful malloc debugging library.
# Do not enable this for production builds...
DOEFENCE  = false

# GNU libc and uClibc want libcrypt.  libc5 wants this disabled...
#BFin LIBRARIES = -lcrypt
LIBRARIES = -L$(ROOTDIR)/lib/$(CONFIG_LIBCDIR)/lib/libc.a
LIBRARIES += -L$(ROOTDIR)/lib/$(CONFIG_LIBCDIR)/lib/libcrypt.a

# If you are running a cross compiler, you may want to set this
# to something more interesting, like "powerpc-linux-".
CROSS = nisa-elf-
CC = $(CROSS)gcc
AR = $(CROSS)ar
STRIPTOOL = $(CROSS)strip

# To compile vs uClibc, just use the compiler wrapper built by uClibc...
# Everything should compile and work as expected these days...
#CC = /usr/i386-linux-uclibc/usr/bin/i386-uclibc-gcc
#USE_SYSTEM_PWD_GRP = true


# To compile vs some other alternative libc, you may need to use/adjust
# the following lines to meet your needs...
#LIBCDIR=/usr/i486-linuxlibc1/
#LDFLAGS+=-nostdlib
#LIBRARIES = $(LIBCDIR)/libc.a -lgcc
#CROSS_CFLAGS+=-nostdinc -I$(LIBCDIR)/include -I$(GCCINCDIR)
#GCCINCDIR = $(shell gcc -print-search-dirs | sed -ne "s/install: \(.*\)/\1include/gp")

ARFLAGS = -r

#--------------------------------------------------------


# use '-Os' optimization if available, else use -O2
OPTIMIZATION = $(shell if $(CC) -Os -S -o /dev/null -xc /dev/null >/dev/null 2>&1; \
    then echo "-Os"; else echo "-O2" ; fi)

WARNINGS = -Wall

ifeq ($(strip $(DODMALLOC)),true)
    # For testing mem leaks with dmalloc
    CFLAGS+=-DDMALLOC
    LIBRARIES+= -ldmalloc
    # Force debug=true, since this is useless when not debugging...
    DODEBUG = true
else
    ifeq ($(strip $(DOEFENCE)),true)
	LIBRARIES+= -lefence
	# Force debug=true, since this is useless when not debugging...
	DODEBUG = true
    endif
endif
ifeq ($(strip $(DODEBUG)),true)
    CFLAGS  += $(WARNINGS) -g -D_GNU_SOURCE
    LDFLAGS += -Wl,-warn-common 
    STRIP    =
else
    CFLAGS  += $(WARNINGS) $(OPTIMIZATION) -fomit-frame-pointer -D_GNU_SOURCE 
    LDFLAGS += -s -Wl,-warn-common
    STRIP    = $(STRIPTOOL) --remove-section=.note --remove-section=.comment $(PROG)
endif
ifeq ($(strip $(DODEBUG)),true)
    LDFLAGS += --static
    #
    #use '-ffunction-sections -fdata-sections' and '--gc-sections' (if they 
    # work) to try and strip out any unused junk.  Doesn't do much for me, 
    # but you may want to give it a shot...
    #
    #ifeq ($(shell $(CC) -ffunction-sections -fdata-sections -S \
    #	-o /dev/null -xc /dev/null 2>/dev/null && $(LD) \
    #			--gc-sections -v >/dev/null && echo 1),1)
    #	CFLAGS += -ffunction-sections -fdata-sections
    #	LDFLAGS += --gc-sections
    #endif
endif
ifeq ($(strip $(DOSTATIC)),true)
    LDFLAGS += --static
    #
    #use '-ffunction-sections -fdata-sections' and '--gc-sections' (if they 
    # work) to try and strip out any unused junk.  Doesn't do much for me, 
    # but you may want to give it a shot...
    #
    #ifeq ($(shell $(CC) -ffunction-sections -fdata-sections -S \
    #	-o /dev/null -xc /dev/null 2>/dev/null && $(LD) \
    #			--gc-sections -v >/dev/null && echo 1),1)
    #	CFLAGS += -ffunction-sections -fdata-sections
    #	LDFLAGS += --gc-sections
    #endif
endif
ifndef $(PREFIX)
    PREFIX = `pwd`/_install
endif


TOPDIR:=$(shell /bin/pwd)
OBJECTS   =  tinylogin.o applets.o usage.o
OBJECTS   += $(shell ./tinylogin.sh)
CFLAGS    += -DCONFIG_VER='"$(VERSION)"'
CFLAGS    += -DCONFIG_BT='"$(BUILDTIME)"'
CFLAGS    += -I$(TOPDIR) -I$(TOPDIR)/include

ifeq ($(strip $(USE_SYSTEM_PWD_GRP)),true)
    CFLAGS    += -DUSE_SYSTEM_PWD_GRP
else
    PWD_GRP	= pwd_grp
    PWD_GRP_DIR = $(PWD_GRP)
    PWD_LIB     = libpwd.a
    PWD_CSRC=__getpwent.c pwent.c getpwnam.c getpwuid.c putpwent.c getpw.c \
	    fgetpwent.c __getgrent.c grent.c getgrnam.c getgrgid.c fgetgrent.c \
	    initgroups.c setgroups.c
    PWD_OBJS=$(patsubst %.c,$(PWD_GRP)/%.o, $(PWD_CSRC))
endif
ifeq ($(strip $(USE_SYSTEM_SHADOW)),true)
    CFLAGS+=-DUSE_SYSTEM_SHADOW
endif

LIBBB	  = libbb
LIBBB_LIB = libbb.a
LIBBB_CSRC= change_identity.c libc5.c pwd2spwd.c run_shell.c \
xfuncs.c correct_password.c pw_encrypt.c restricted_shell.c \
setup_environment.c error_msg.c error_msg_and_die.c perror_msg.c \
perror_msg_and_die.c verror_msg.c vperror_msg.c safe_strncpy.c \
get_last_path_component.c concat_path_file.c last_char_is.c \
wfopen.c syslog_msg_with_name.c obscure.c xreadlink.c
LIBBB_OBJS=$(patsubst %.c,$(LIBBB)/%.o, $(LIBBB_CSRC))

LIBBB_MSRC=libbb/messages.c
LIBBB_MESSAGES= full_version name_too_long omitting_directory not_a_directory \
memory_exhausted invalid_date invalid_option io_error dash_dash_help \
write_error too_few_args name_longer_than_foo unknown can_not_create_raw_socket \
nologin_file passwd_file shadow_file gshadow_file group_file securetty_file \
motd_file issue_file _path_login
LIBBB_MOBJ=$(patsubst %,$(LIBBB)/%.o, $(LIBBB_MESSAGES))




# Put user-supplied flags at the end, where they
# have a chance of winning.
CFLAGS += $(CFLAGS_EXTRA)

.EXPORT_ALL_VARIABLES:

all: tinylogin tinylogin.links doc

doc: docs/TinyLogin.txt docs/TinyLogin.1 docs/TinyLogin.html

docs/TinyLogin.txt: docs/tinylogin.pod
	@echo
	@echo TinyLogin Documentation
	@echo
	- pod2text docs/tinylogin.pod > docs/TinyLogin.txt

docs/TinyLogin.1: docs/tinylogin.pod
	- pod2man --center=TinyLogin --release="version $(VERSION)" docs/tinylogin.pod > docs/TinyLogin.1

docs/TinyLogin.html: docs/tinylogin.busybox.net/TinyLogin.html
	- rm -f docs/TinyLogin.html
	- ln -s tinylogin.busybox.net/TinyLogin.html docs/TinyLogin.html

docs/tinylogin.busybox.net/TinyLogin.html: docs/tinylogin.pod
	- pod2html docs/tinylogin.pod > docs/tinylogin.busybox.net/TinyLogin.html
	- rm -f pod2html*

tinylogin: $(PWD_LIB) $(LIBBB_LIB) $(OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $(OBJECTS) $(PWD_LIB) $(LIBBB_LIB) $(LIBRARIES)
	$(STRIP)

$(PWD_OBJS): %.o: %.c Config.h include/tinylogin.h include/applets.h Makefile
	- mkdir -p $(PWD_GRP)
	$(CC) $(CFLAGS) -c $< -o $*.o

libpwd.a: $(PWD_OBJS)
	$(AR) $(ARFLAGS) $@ $^

libbb.a:  $(LIBBB_MOBJ) $(LIBBB_AROBJS) $(LIBBB_OBJS)
	$(AR) $(ARFLAGS) $@ $^

$(LIBBB_OBJS): %.o: %.c Config.h include/tinylogin.h include/applets.h include/libbb.h Makefile
	$(CC) $(CFLAGS) -c $< -o $*.o

$(LIBBB_MOBJ): $(LIBBB_MSRC)
	$(CC) $(CFLAGS) -DL_$(patsubst libbb/%,%,$*) -c $< -o $*.o

$(LIBBB_AROBJS): $(LIBBB_ARCSRC)
	$(CC) $(CFLAGS) -DL_$(patsubst libbb/%,%,$*) -c $< -o $*.o


tinylogin.links: Config.h include/applets.h
	- ./tinylogin.mkll | sort >$@

$(OBJECTS): %.o: %.c Config.h include/tinylogin.h include/applets.h Makefile

clean:
	- rm -f tinylogin tinylogin.links *~ core
	- find -name \*.o -exec rm -f {} \;
	- find -name \*.a -exec rm -f {} \;
	- find -name pod2htm\* -exec rm -f {} \;
	- rm -rf _install
	- rm -f rm ./pwd_grp/libpwd.a docs/TinyLogin.txt docs/TinyLogin.1 \
		docs/TinyLogin.html docs/tinylogin.busybox.net/TinyLogin.html

distclean: clean
	- rm -f tinylogin

install: $(PWD_LIB) tinylogin tinylogin.links doc
	@./install.sh $(PREFIX)

install-hardlinks: tinylogin tinylogin.links
	@./install.sh $(PREFIX) --hardlinks

dist release: distclean doc
	- find -name pod2htm\* -exec rm -f {} \;
	cd ..;					\
	rm -rf tinylogin-$(VERSION);		\
	cp -a tinylogin tinylogin-$(VERSION);	\
						\
	find tinylogin-$(VERSION)/ -type d	\
				 -name CVS	\
				 -print		\
		| xargs rm -rf;			\
						\
	find tinylogin-$(VERSION)/ -type f	\
				 -name .cvsignore \
				 -print		\
		| xargs rm -f;			\
						\
	find tinylogin-$(VERSION)/ -type f	\
				 -name .\#*	\
				 -print		\
		| xargs rm -f;			\
						\
	tar -cvzf tinylogin-$(VERSION).tar.gz tinylogin-$(VERSION)/;

