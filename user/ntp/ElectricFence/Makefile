# Makefile.in generated automatically by automake 1.5 from Makefile.am.

# Copyright 1994, 1995, 1996, 1997, 1998, 1999, 2000, 2001
# Free Software Foundation, Inc.
# This Makefile.in is free software; the Free Software Foundation
# gives unlimited permission to copy and/or distribute it,
# with or without modifications, as long as this notice is preserved.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY, to the extent permitted by law; without
# even the implied warranty of MERCHANTABILITY or FITNESS FOR A
# PARTICULAR PURPOSE.



# Harlan Stenn <stenn@whimsy.udel.edu>
# Converted the original Makefile (now in Makefile-) to Makefile.am
# in July of '00

SHELL = /bin/sh

srcdir = .
top_srcdir = ..

prefix = /usr/local
exec_prefix = ${prefix}

bindir = ${exec_prefix}/bin
sbindir = ${exec_prefix}/sbin
libexecdir = ${exec_prefix}/libexec
datadir = ${prefix}/share
sysconfdir = ${prefix}/etc
sharedstatedir = ${prefix}/com
localstatedir = ${prefix}/var
libdir = ${exec_prefix}/lib
infodir = ${prefix}/info
mandir = ${prefix}/man
includedir = ${prefix}/include
oldincludedir = /usr/include
pkgdatadir = $(datadir)/ntp
pkglibdir = $(libdir)/ntp
pkgincludedir = $(includedir)/ntp
top_builddir = ..

ACLOCAL = ${SHELL} /home/gerg/new-wave.dist/user/ntp/missing --run aclocal
AUTOCONF = ${SHELL} /home/gerg/new-wave.dist/user/ntp/missing --run autoconf
AUTOMAKE = ${SHELL} /home/gerg/new-wave.dist/user/ntp/missing --run automake
AUTOHEADER = ${SHELL} /home/gerg/new-wave.dist/user/ntp/missing --run autoheader

INSTALL = /usr/bin/install -c
INSTALL_PROGRAM = ${INSTALL}
INSTALL_DATA = ${INSTALL} -m 644
INSTALL_SCRIPT = ${INSTALL}
INSTALL_HEADER = $(INSTALL_DATA)
transform = s,x,x,
NORMAL_INSTALL = :
PRE_INSTALL = :
POST_INSTALL = :
NORMAL_UNINSTALL = :
PRE_UNINSTALL = :
POST_UNINSTALL = :
build_alias = 
build_triplet = i686-pc-linux-gnu
host_alias = 
host_triplet = i686-pc-linux-gnu
target_alias = 
target_triplet = i686-pc-linux-gnu
AMTAR = ${SHELL} /home/gerg/new-wave.dist/user/ntp/missing --run tar
AUTOKEY = 
AWK = mawk
#CC = gcc
CFLAGS +=  -Wall -Wcast-qual -Wmissing-prototypes -Wpointer-arith -Wshadow -Wstrict-prototypes -pipe
CHUTEST = 
CLKTEST = 
CPP = $(CC) -E
DCFD = 
DEPDIR = .deps
EF_LIBS = 
EF_PROGS = 
EXEEXT = 
INSTALL_STRIP_PROGRAM = ${SHELL} $(install_sh) -c -s
#LDFLAGS = 
LIBPARSE = 
LIBRSAREF = 
LN_S = ln -s
MAKE_ADJTIMED = 
MAKE_CHECK_Y2K = 
MAKE_LIBPARSE = 
MAKE_LIBPARSE_KERNEL = 
MAKE_LIBRSAREF = 
MAKE_NTPTIME = ntptime
MAKE_NTP_GENKEYS = 
MAKE_PARSEKMODULE = 
MAKE_TICKADJ = tickadj
MAKE_TIMETRIM = 
OBJEXT = o
OPENSSL = 
OPENSSL_INC = 
OPENSSL_LIB = 
PACKAGE = ntp
PATH_PERL = /usr/bin/perl
PATH_SH = /bin/sh
PROPDELAY = 
RANLIB = ranlib
RSADIR = 
RSAOBJS = 
RSAREF = 
RSASRCS = 
TESTDCF = 
U = 
VERSION = 4.1.1
am__include = include
am__quote = 
install_sh = /home/gerg/new-wave.dist/user/ntp/install-sh

EXTRA_DIST = libefence.3 CHANGES
libefence_a_SOURCES = efence.h efence.c page.c print.c
check_PROGRAMS = 
EXTRA_PROGRAMS = eftest tstheap
# TESTS = eftest tstheap
noinst_LIBRARIES = 
EXTRA_LIBRARIES = libefence.a
LDADD = libefence.a
subdir = ElectricFence
mkinstalldirs = $(SHELL) $(top_srcdir)/mkinstalldirs
CONFIG_HEADER = $(top_builddir)/config.h
CONFIG_CLEAN_FILES =
LIBRARIES = $(noinst_LIBRARIES)

libefence_a_AR = $(AR) cru
libefence_a_LIBADD =
am_libefence_a_OBJECTS = efence.$(OBJEXT) page.$(OBJEXT) print.$(OBJEXT)
libefence_a_OBJECTS = $(am_libefence_a_OBJECTS)
EXTRA_PROGRAMS = eftest$(EXEEXT) tstheap$(EXEEXT)
check_PROGRAMS = 
eftest_SOURCES = eftest.c
eftest_OBJECTS = eftest.$(OBJEXT)
eftest_LDADD = $(LDADD)
eftest_DEPENDENCIES = libefence.a
eftest_LDFLAGS =
tstheap_SOURCES = tstheap.c
tstheap_OBJECTS = tstheap.$(OBJEXT)
tstheap_LDADD = $(LDADD)
tstheap_DEPENDENCIES = libefence.a
tstheap_LDFLAGS =

DEFS = -DHAVE_CONFIG_H
DEFAULT_INCLUDES =  -I. -I$(srcdir) -I$(top_builddir)
CPPFLAGS = 
#LDFLAGS = 
LIBS = 
depcomp = $(SHELL) $(top_srcdir)/depcomp
DEP_FILES = $(DEPDIR)/efence.Po $(DEPDIR)/eftest.Po \
	$(DEPDIR)/page.Po $(DEPDIR)/print.Po \
	$(DEPDIR)/tstheap.Po
COMPILE = $(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) \
	$(CPPFLAGS) $(AM_CFLAGS) $(CFLAGS)
CCLD = $(CC)
LINK = $(CCLD) $(AM_CFLAGS) $(AM_LDFLAGS) $(LDFLAGS) -o $@
LIBS += $(LDLIBS$(LDLIBS_$@))
DIST_SOURCES = $(libefence_a_SOURCES) eftest.c tstheap.c
DIST_COMMON = README COPYING Makefile.am Makefile.in
SOURCES = $(libefence_a_SOURCES) eftest.c tstheap.c

all: all-am

.SUFFIXES:
.SUFFIXES: .c .o .obj
$(srcdir)/Makefile.in:  Makefile.am  $(top_srcdir)/configure.in $(ACLOCAL_M4)
	cd $(top_srcdir) && \
	  $(AUTOMAKE) --gnu  ElectricFence/Makefile
Makefile:  $(srcdir)/Makefile.in  $(top_builddir)/config.status
	cd $(top_builddir) && \
	  CONFIG_HEADERS= CONFIG_LINKS= \
	  CONFIG_FILES=$(subdir)/$@ $(SHELL) ./config.status

AR = ar

clean-noinstLIBRARIES:
	-test -z "$(noinst_LIBRARIES)" || rm -f $(noinst_LIBRARIES)
libefence.a: $(libefence_a_OBJECTS) $(libefence_a_DEPENDENCIES) 
	-rm -f libefence.a
	$(libefence_a_AR) libefence.a $(libefence_a_OBJECTS) $(libefence_a_LIBADD)
	$(RANLIB) libefence.a

clean-checkPROGRAMS:
	-test -z "$(check_PROGRAMS)" || rm -f $(check_PROGRAMS)
eftest$(EXEEXT): $(eftest_OBJECTS) $(eftest_DEPENDENCIES) 
	@rm -f eftest$(EXEEXT)
	$(LINK) $(eftest_LDFLAGS) $(eftest_OBJECTS) $(eftest_LDADD) $(LIBS)
tstheap$(EXEEXT): $(tstheap_OBJECTS) $(tstheap_DEPENDENCIES) 
	@rm -f tstheap$(EXEEXT)
	$(LINK) $(tstheap_LDFLAGS) $(tstheap_OBJECTS) $(tstheap_LDADD) $(LIBS)

mostlyclean-compile:
	-rm -f *.$(OBJEXT) core *.core

distclean-compile:
	-rm -f *.tab.c

include $(DEPDIR)/efence.Po
include $(DEPDIR)/eftest.Po
include $(DEPDIR)/page.Po
include $(DEPDIR)/print.Po
include $(DEPDIR)/tstheap.Po

distclean-depend:
	-rm -rf $(DEPDIR)

.c.o:
	source='$<' object='$@' libtool=no \
	depfile='$(DEPDIR)/$*.Po' tmpdepfile='$(DEPDIR)/$*.TPo' \
	$(CCDEPMODE) $(depcomp) \
	$(COMPILE) -c `test -f $< || echo '$(srcdir)/'`$<

.c.obj:
	source='$<' object='$@' libtool=no \
	depfile='$(DEPDIR)/$*.Po' tmpdepfile='$(DEPDIR)/$*.TPo' \
	$(CCDEPMODE) $(depcomp) \
	$(COMPILE) -c `cygpath -w $<`
CCDEPMODE = depmode=gcc
uninstall-info-am:

tags: TAGS

ID: $(HEADERS) $(SOURCES) $(LISP) $(TAGS_FILES)
	list='$(SOURCES) $(HEADERS) $(TAGS_FILES)'; \
	unique=`for i in $$list; do \
	    if test -f "$$i"; then echo $$i; else echo $(srcdir)/$$i; fi; \
	  done | \
	  $(AWK) '    { files[$$0] = 1; } \
	       END { for (i in files) print i; }'`; \
	mkid -fID $$unique $(LISP)

TAGS:  $(HEADERS) $(SOURCES)  $(TAGS_DEPENDENCIES) \
		$(TAGS_FILES) $(LISP)
	tags=; \
	here=`pwd`; \
	list='$(SOURCES) $(HEADERS) $(TAGS_FILES)'; \
	unique=`for i in $$list; do \
	    if test -f "$$i"; then echo $$i; else echo $(srcdir)/$$i; fi; \
	  done | \
	  $(AWK) '    { files[$$0] = 1; } \
	       END { for (i in files) print i; }'`; \
	test -z "$(ETAGS_ARGS)$$unique$(LISP)$$tags" \
	  || etags $(ETAGS_ARGS) $$tags  $$unique $(LISP)

GTAGS:
	here=`CDPATH=: && cd $(top_builddir) && pwd` \
	  && cd $(top_srcdir) \
	  && gtags -i $(GTAGS_ARGS) $$here

distclean-tags:
	-rm -f TAGS ID GTAGS GRTAGS GSYMS GPATH

DISTFILES = $(DIST_COMMON) $(DIST_SOURCES) $(TEXINFOS) $(EXTRA_DIST)

top_distdir = ..
distdir = $(top_distdir)/$(PACKAGE)-$(VERSION)

distdir: $(DISTFILES)
	@for file in $(DISTFILES); do \
	  if test -f $$file; then d=.; else d=$(srcdir); fi; \
	  dir=`echo "$$file" | sed -e 's,/[^/]*$$,,'`; \
	  if test "$$dir" != "$$file" && test "$$dir" != "."; then \
	    $(mkinstalldirs) "$(distdir)/$$dir"; \
	  fi; \
	  if test -d $$d/$$file; then \
	    cp -pR $$d/$$file $(distdir) \
	    || exit 1; \
	  else \
	    test -f $(distdir)/$$file \
	    || cp -p $$d/$$file $(distdir)/$$file \
	    || exit 1; \
	  fi; \
	done
check-am: all-am
	$(MAKE) $(AM_MAKEFLAGS) $(check_PROGRAMS)
	$(MAKE) $(AM_MAKEFLAGS) check-local
check: check-am
all-am: Makefile $(LIBRARIES)

installdirs:

install: install-am
install-exec: install-exec-am
install-data: install-data-am
uninstall: uninstall-am

install-am: all-am
	@$(MAKE) $(AM_MAKEFLAGS) install-exec-am install-data-am

installcheck: installcheck-am
install-strip:
	$(MAKE) $(AM_MAKEFLAGS) INSTALL_PROGRAM="$(INSTALL_STRIP_PROGRAM)" \
	  `test -z '$(STRIP)' || \
	    echo "INSTALL_PROGRAM_ENV=STRIPPROG='$(STRIP)'"` install
mostlyclean-generic:

clean-generic:

distclean-generic:
	-rm -f Makefile $(CONFIG_CLEAN_FILES) stamp-h stamp-h[0-9]*

maintainer-clean-generic:
	@echo "This command is intended for maintainers to use"
	@echo "it deletes files that may require special tools to rebuild."
clean: clean-am

clean-am: clean-checkPROGRAMS clean-generic clean-noinstLIBRARIES \
	mostlyclean-am

distclean: distclean-am

distclean-am: clean-am distclean-compile distclean-depend \
	distclean-generic distclean-tags

dvi: dvi-am

dvi-am:

info: info-am

info-am:

install-data-am:

install-exec-am:

install-info: install-info-am

install-man:

installcheck-am:

maintainer-clean: maintainer-clean-am

maintainer-clean-am: distclean-am maintainer-clean-generic

mostlyclean: mostlyclean-am

mostlyclean-am: mostlyclean-compile mostlyclean-generic

uninstall-am: uninstall-info-am

.PHONY: GTAGS all all-am check check-am check-local clean \
	clean-checkPROGRAMS clean-generic clean-noinstLIBRARIES \
	distclean distclean-compile distclean-depend distclean-generic \
	distclean-tags distdir dvi dvi-am info info-am install \
	install-am install-data install-data-am install-exec \
	install-exec-am install-info install-info-am install-man \
	install-strip installcheck installcheck-am installdirs \
	maintainer-clean maintainer-clean-generic mostlyclean \
	mostlyclean-compile mostlyclean-generic tags uninstall \
	uninstall-am uninstall-info-am


# Un-comment the following if you are running HP/UX.
# CFLAGS= -Aa -g -D_HPUX_SOURCE -DPAGE_PROTECTION_VIOLATED_SIGNAL=SIGBUS

# Un-comment the following if you are running AIX. This makes sure you won't
# get the shared-library malloc() rather than the Electric Fence malloc().
# COMPILE THE PROGRAMS YOU ARE DEBUGGING WITH THESE FLAGS, TOO.
# CFLAGS= -g -bnso -bnodelcsect -bI:/lib/syscalls.exp

# Un-comment the following if you are running SunOS 4.X
# Note the definition of PAGE_PROTECTION_VIOLATED_SIGNAL. This may vary
# depend on what version of Sun hardware you have.
# You'll probably have to link the program you are debugging with -Bstatic
# as well if using Sun's compiler, -static if using GCC.
# CFLAGS= -g -Bstatic -DPAGE_PROTECTION_VIOLATED_SIGNAL=SIGBUS

check-local:
	test ! -f eftest  || ./eftest
	test ! -f tstheap || ./tstheap 3072
# Tell versions [3.59,3.63) of GNU make to not export all variables.
# Otherwise a system limit (for SysV at least) may be exceeded.
.NOEXPORT:
