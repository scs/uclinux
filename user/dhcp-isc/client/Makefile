# Makefile.conf
#
# Copyright (c) 1996, 1997, 1998, 1999 The Internet Software Consortium.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 3. Neither the name of The Internet Software Consortium nor the names of its
#    contributors may be used to endorse or promote products derived
#    from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE INTERNET SOFTWARE CONSORTIUM AND
# CONTRIBUTORS ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING,
# BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL
# THE INTERNET SOFTWARE CONSORTIUM OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
# INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
# OF THE POSSIBILITY OF SUCH DAMAGE.
#

## Defaults...
SCRIPT = none
BINDIR = /usr/sbin
CLIENTBINDIR=/sbin
ADMMANEXT = .0
FFMANEXT = .0
ADMMANDIR = /usr/share/man/cat8
FFMANDIR = /usr/share/man/cat5
INSTALL = install -c
MANINSTALL = install -c -m 444
CHMOD = chmod
CATMANPAGES =
MANCAT = cat
ETC = /etc
VARRUN = /var/run
VARDB = /var/db
CLIENT_PATH = '"PATH=/usr/ucb:/usr/bin:/usr/sbin:/bin:/sbin"'

# Major version number (if applicable)
##--majver--
MAJORVERSION=2
##--majver--

# Minor version number (if applicable)
##--minver--
MINORVERSION=2
##--minver--

## Porting::
#
# For each supported operating system, there is a block of text below
# beginning with #--os-name-- and ending with #--os-name--.   Between
# these delimiters are assignments, commented out, which define the
# Makefile variables required for that operating system.
#
# The configure shell script figures out what operating system it's
# being run on and then runs Makefile.dist through a sed script which
# removes the comment characters from the appropriate set of
# assignments, and writes the output to Makefile.

## AIX 4.1.5.0
##--aix--
#CF = cf/aix.h
#CC=cc -Daix
#INSTALL=/usr/ucb/install
#MANINSTALL=/usr/ucb/install
#ADMMANEXT = .8
#FFMANEXT = .5
#VARRUN = /etc
#VARDB = /etc
##--aix--

## NEXTSTEP 3.x,4.x
##--nextstep--
#LIBS =
#CF = cf/nextstep.h
#CC=cc
#COPTS = -Wall
#BINDIR=/usr/etc
#ADMMANDIR = /usr/local/man/cat8
#FFMANDIR = /usr/local/man/cat5
#ADMMANEXT = .8
#FFMANEXT = .5
#VARRUN = /etc
#VARDB = /etc
##--nextstep--

## SunOS 4.1
##--sunos4--
#LIBS = -lresolv
#CF = cf/sunos4.h
#BINDIR=/usr/etc
#CLIENTBINDIR=/etc
#ADMMANEXT = .8
#FFMANEXT = .5
#VARRUN = /etc
#VARDB = /etc
##--sunos4--

## Solaris 2.5 (with gcc)
##--sunos5-gcc--
#INSTALL=/usr/ucb/install
#MANINSTALL=/usr/ucb/install
#LIBS = -lresolv -lsocket -lnsl -lgen
#CC=gcc
#COPTS = -Wall -Wno-unused -Wno-implicit -Wno-comment \
#	 -Wno-uninitialized -Wno-char-subscripts -Werror
#CF = cf/sunos5-5.h
#ADMMANDIR = /usr/share/man/cat1m
#ADMMANEXT = .1m
#FFMANDIR = /usr/share/man/cat4
#FFMANEXT = .4
#VARRUN = /etc
#VARDB = /etc
#SCRIPT=solaris
##--sunos5-gcc--

## Solaris 2.5 (with Sun cc)
##--sunos5-cc--
#INSTALL=/usr/ucb/install
#MANINSTALL=/usr/ucb/install
#LIBS = -lresolv -lsocket -lnsl -lgen
#CC=cc
#COPTS = -D__svr4__
#CF = cf/sunos5-5.h
#ADMMANDIR = /usr/share/man/cat1m
#ADMMANEXT = .1m
#FFMANDIR = /usr/share/man/cat4
#FFMANEXT = .4
#VARRUN = /etc
#VARDB = /etc
#SCRIPT=solaris
##--sunos5-cc--

## DEC Alpha/OSF1
##--alphaosf--
#CC=cc -std0
#INSTALL=/usr/ucb/installbsd
#MANINSTALL=/usr/ucb/installbsd
#LIBS=
#CF = cf/alphaosf.h
#ADMMANEXT = .8
#FFMANEXT = .5
#VARDB = /etc
##--alphaosf--

## BSD/OS 2.1
##--bsdos--
#LIBS= -lresolv
#CC=gcc2
#CF = cf/bsdos.h
##--bsdos--

## FreeBSD
##--freebsd--
#CF = cf/freebsd.h
#SCRIPT=freebsd
##--freebsd--

## Rhapsody
##--rhapsody--
#CF = cf/rhapsody.h
#COPTS  = -Wall -Wno-unused -Wno-implicit -Wno-comment \
#	  -Wno-uninitialized -Werror -pipe
#SCRIPT=rhapsody
##--rhapsody--

## NetBSD
##--netbsd--
#CF = cf/netbsd.h
#COPTS  = -Wall -Wstrict-prototypes -Wno-unused -Wno-implicit -Wno-comment \
#	  -Wno-uninitialized -Werror -pipe
#SCRIPT=netbsd
##--netbsd--

## Ultrix
##--ultrix--
#BINDIR = /usr/etc
#CLIENTBINDIR=/etc
#VARRUN = /etc
#VARDB = /etc
#CF = cf/ultrix.h
#ADMMANDIR = /usr/man/man8
#ADMMANEXT = .8
#FFMANDIR = /usr/man/man5
#FFMANEXT = .5
##--ultrix--

## Linux 1.x
##--linux-1--
#COPTS = -DLINUX_MAJOR=$(MAJORVERSION) -DLINUX_MINOR=$(MINORVERSION)
#CF = cf/linux.h
#ADMMANDIR = /usr/man/man8
#ADMMANEXT = .8
#FFMANDIR = /usr/man/man5
#FFMANEXT = .5
#MANCAT = man
#VARRUN = /var/run
#VARDB = /var/state/dhcp	# see rationale in includes/cf/linux.h
#SCRIPT=linux
##--linux-1--

## Linux 2.0
##--linux-2.0--
#COPTS = -DLINUX_MAJOR=$(MAJORVERSION) -DLINUX_MINOR=$(MINORVERSION)
#CF = cf/linux.h
#ADMMANDIR = /usr/man/man8
#ADMMANEXT = .8
#FFMANDIR = /usr/man/man5
#FFMANEXT = .5
#MANCAT = man
#VARRUN = /var/run
#VARDB = /var/state/dhcp	# see rationale in includes/cf/linux.h
#SCRIPT=linux
##--linux-2.0--

## Linux 2.1
##--linux-2.1--
#COPTS = -DLINUX_MAJOR=$(MAJORVERSION) -DLINUX_MINOR=$(MINORVERSION)
#CF = cf/linux.h
#ADMMANDIR = /usr/man/man8
#ADMMANEXT = .8
#FFMANDIR = /usr/share/man/man5
#FFMANEXT = .5
#MANCAT = man
#VARRUN = /var/run
#VARDB = /var/state/dhcp	# see rationale in includes/cf/linux.h
#SCRIPT=linux
##--linux-2.1--

## Linux 2.2
#--linux-2.2--
COPTS = -DLINUX_MAJOR=$(MAJORVERSION) -DLINUX_MINOR=$(MINORVERSION)
CF = cf/linux.h
ADMMANDIR = /usr/man/man8
ADMMANEXT = .8
FFMANDIR = /usr/share/man/man5
FFMANEXT = .5
MANCAT = man
VARRUN = /var/run
VARDB = /var/state/dhcp	# see rationale in includes/cf/linux.h
SCRIPT=linux
#--linux-2.2--

## SCO
##--sco--
#CF = cf/sco.h
#PREDEFINES=-DSCO -DBROKEN_ANSI
#BINDIR = /usr/etc
#CLIENTBINDIR=/etc
#ADMMANDIR = /usr/man/cat.ADMN
#ADMMANEXT = .ADMN.Z
#FFMANDIR = /usr/man/cat.SFF
#FFMANEXT = .SFF.Z
#INSTALL = cp
#MANFROM = <
#MANINSTALL = compress
#MANTO = >
#VARRUN = /etc
#VARDB = /etc
#CATMANPAGES=
##--sco--

## QNX
##--qnx--
#CF = cf/qnx.h
#ADMMANDIR = /usr/man/man8
#ADMMANEXT = .8
#FFMANDIR = /usr/man/man5
#FFMANEXT = .5
#MANCAT = man
#VARRUN = /etc
#COPTS=-w3 -Dlint
#LFLAGS=$(DEBUG) "-Wl,op symfile" -l socket
#MANINSTALL = /bin/true 
#INSTALL = cp
#BINDIR = /etc
#CLIENTBINDIR = /etc
##--qnx--

## CygWin32
##--cygwin32--
#CF = cf/cygwin32.h
#ADMMANDIR = /usr/man/man8
#ADMMANEXT = .8
#FFMANDIR = /usr/man/man5
#FFMANEXT = .5
#VARRUN = /etc
#MANINSTALL = /bin/true 
#INSTALL = cp
#BINDIR = /etc
#CLIENTBINDIR = /etc
#CC=/usr/local/i386-unknown-cygwin32/bin/gcc
#AR=/usr/local/i386-unknown-cygwin32/bin/ar
#AS=/usr/local/i386-unknown-cygwin32/bin/as
#LD=/usr/local/i386-unknown-cygwin32/bin/ld
#NM=/usr/local/i386-unknown-cygwin32/bin/nm
#RANLIB=/usr/local/i386-unknown-cygwin32/bin/ranlib
#STRIP=/usr/local/i386-unknown-cygwin32/bin/strip
##--cygwin32--

## IRIX 6.x
##--irix--
#LIBS = -lbind
#LFLAGS=$(DEBUG) -L/usr/local/lib -Wl,-woff,84 -Wl,-woff,85 -Wl,-woff,134
#CC=gcc
#COPTS = -I/usr/local/include
#CF = cf/irix.h
#BINDIR = /usr/local/etc
#ADMMANDIR = /usr/local/man/man8
#ADMMANEXT = .8
#FFMANDIR = /usr/local/man/man5
#FFMANEXT = .5
#MANCAT = man
#INSTALL = install
#MANINSTALL = install
#CHMOD = chmod
#ETC = /etc
#VARRUN = /etc
#VARDB = /usr/local/etc/dhcp
##--irix--
# Makefile.dist
#
# Copyright (c) 1996, 1997, 1999 The Internet Software Consortium.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 3. Neither the name of The Internet Software Consortium nor the names of its
#    contributors may be used to endorse or promote products derived
#    from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE INTERNET SOFTWARE CONSORTIUM AND
# CONTRIBUTORS ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING,
# BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL
# THE INTERNET SOFTWARE CONSORTIUM OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
# INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
# OF THE POSSIBILITY OF SUCH DAMAGE.
#

CATMANPAGES = dhclient.cat8 dhclient.conf.cat5 dhclient-script.cat8 \
	      dhclient.leases.cat5
SEDMANPAGES = dhclient.man8 dhclient.conf.man5 dhclient-script.man8 \
	      dhclient.leases.man5
SRCS   = dhclient.c clparse.c
OBJS   = dhclient.o clparse.o
PROG   = dhclient
MAN    = dhclient.8 dhclient.conf.5 dhclient-script.8 dhclient.leases.5

# DEBUG  = -g
INCLUDES += -I.. -I../includes
DHCPLIB = ../common/libdhcp.a
CFLAGS += $(PREDEFINES) $(INCLUDES) $(COPTS) -DCLIENT_PATH=${CLIENT_PATH}

all:	$(PROG) $(CATMANPAGES)

install: all
	for dir in $(CLIENTBINDIR) $(ETC) $(FFMANDIR) $(ADMMANDIR) $(VARDB); \
	do \
	  foo=""; \
	  for bar in `echo $(DESTDIR)$${dir} |tr / ' '`; do \
	    foo=$${foo}/$$bar; \
	    if [ ! -d $$foo ]; then \
	      mkdir $$foo; \
	      chmod 755 $$foo; \
	    fi; \
	  done; \
	done
	$(INSTALL) dhclient $(DESTDIR)$(CLIENTBINDIR)
	$(CHMOD) 755 $(DESTDIR)$(CLIENTBINDIR)/dhclient
	if [ x$(SCRIPT) = xnone ]; then \
	  echo "No client script available."; \
	else \
	  $(INSTALL) scripts/$(SCRIPT) $(DESTDIR)$(ETC)/dhclient-script; \
	  $(CHMOD) 700 $(DESTDIR)$(ETC)/dhclient-script; \
	fi
	$(MANINSTALL) $(MANFROM) dhclient.$(MANCAT)8 $(MANTO) \
			$(DESTDIR)$(ADMMANDIR)/dhclient$(ADMMANEXT)
	$(MANINSTALL) $(MANFROM) dhclient-script.$(MANCAT)8 $(MANTO) \
			$(DESTDIR)$(ADMMANDIR)/dhclient-script$(ADMMANEXT)
	$(MANINSTALL) $(MANFROM) dhclient.conf.$(MANCAT)5 $(MANTO) \
			$(DESTDIR)$(FFMANDIR)/dhclient.conf$(FFMANEXT)
	$(MANINSTALL) $(MANFROM) dhclient.leases.$(MANCAT)5 $(MANTO) \
			$(DESTDIR)$(FFMANDIR)/dhclient.leases$(FFMANEXT)

clean:
	-rm -f $(OBJS) *.gdb *.elf
	
realclean: clean
	-rm -f $(PROG) $(CATMANPAGES) $(SEDMANPAGES) *~ #*

distclean: realclean
	-rm -f Makefile

# These should only be done on 4.4 BSD-based systems, since the mandoc
# macros aren't available on older unices.   Catted man pages are
# provided in the distribution so that this doesn't become a problem.

dhclient.cat8:	dhclient.man8
	nroff -man dhclient.man8 >dhclient.cat8

dhclient.man8: dhclient.8
	sed -e "s#ETCDIR#$(ETC)#g" -e "s#DBDIR#$(VARDB)#g" \
		-e "s#RUNDIR#$(VARRUN)#g" < dhclient.8 >dhclient.man8

dhclient-script.cat8:	dhclient-script.man8
	nroff -man dhclient-script.man8 >dhclient-script.cat8

dhclient-script.man8:	dhclient-script.8
	sed -e "s#ETCDIR#$(ETC)#g" -e "s#DBDIR#$(VARDB)#g" \
		-e "s#RUNDIR#$(VARRUN)#g" < dhclient-script.8 \
						>dhclient-script.man8

dhclient.conf.man5:	dhclient.conf.5
	sed -e "s#ETCDIR#$(ETC)#g" -e "s#DBDIR#$(VARDB)#g" \
		-e "s#RUNDIR#$(VARRUN)#g" < dhclient.conf.5 \
						>dhclient.conf.man5

dhclient.conf.cat5:	dhclient.conf.man5
	nroff -man dhclient.conf.man5 >dhclient.conf.cat5

dhclient.leases.man5:	dhclient.leases.5
	sed -e "s#ETCDIR#$(ETC)#g" -e "s#DBDIR#$(VARDB)#g" \
		-e "s#RUNDIR#$(VARRUN)#g" < dhclient.leases.5 \
						>dhclient.leases.man5

dhclient.leases.cat5:	dhclient.leases.man5
	nroff -man dhclient.leases.man5 >dhclient.leases.cat5

dhclient:	$(OBJS) $(DHCPLIB)
	$(CC) $(LDFLAGS) $(LFLAGS) -o $(PROG) $(OBJS) $(DHCPLIB) $(LIBS) $(LDLIBS)

romfs:
	$(ROMFSINST) /bin/dhclient

# Dependencies (semi-automatically-generated)

dhclient.o: dhclient.c ../includes/dhcpd.h \
 ../includes/cdefs.h ../includes/osdep.h ../includes/site.h \
 ../includes/cf/netbsd.h ../includes/dhcp.h \
 ../includes/tree.h ../includes/hash.h ../includes/inet.h \
 ../includes/sysconf.h ../includes/version.h
clparse.o: clparse.c ../includes/dhcpd.h \
 ../includes/cdefs.h ../includes/osdep.h ../includes/site.h \
 ../includes/cf/netbsd.h ../includes/dhcp.h \
 ../includes/tree.h ../includes/hash.h ../includes/inet.h \
 ../includes/sysconf.h ../includes/dhctoken.h
