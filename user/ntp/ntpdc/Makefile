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



#AUTOMAKE_OPTIONS = ../util/ansi2knr no-dependencies

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
CPP = $(CC)
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

AUTOMAKE_OPTIONS = ../util/ansi2knr
bin_PROGRAMS = ntpdc
INCLUDES = -I$(top_srcdir)/include
# LDADD might need RESLIB and ADJLIB
LDADD = version.o ../libntp/libntp.a  
DISTCLEANFILES = .version version.c
noinst_HEADERS = ntpdc.h
#EXTRA_DIST = ntpdc.mak
ETAGS_ARGS = Makefile.am

ntpdc_SOURCES = ntpdc.c ntpdc_ops.c
subdir = ntpdc
mkinstalldirs = $(SHELL) $(top_srcdir)/mkinstalldirs
CONFIG_HEADER = $(top_builddir)/config.h
CONFIG_CLEAN_FILES =
bin_PROGRAMS = ntpdc$(EXEEXT)
PROGRAMS = $(bin_PROGRAMS)

am_ntpdc_OBJECTS = ntpdc$U.$(OBJEXT) ntpdc_ops$U.$(OBJEXT)
ntpdc_OBJECTS = $(am_ntpdc_OBJECTS)
ntpdc_LDADD = $(LDADD)
ntpdc_DEPENDENCIES = version.o ../libntp/libntp.a
ntpdc_LDFLAGS =

DEFS = -DHAVE_CONFIG_H
DEFAULT_INCLUDES =  -I. -I$(srcdir) -I$(top_builddir)
CPPFLAGS = 
#LDFLAGS = 
LIBS = 
depcomp = $(SHELL) $(top_srcdir)/depcomp
DEP_FILES = $(DEPDIR)/ntpdc$U.Po $(DEPDIR)/ntpdc_ops$U.Po
COMPILE = $(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) \
	$(CPPFLAGS) $(AM_CFLAGS) $(CFLAGS)
CCLD = $(CC)
LINK = $(CCLD) $(AM_CFLAGS) $(AM_LDFLAGS) $(LDFLAGS) -o $@
LIBS += $(LDLIBS$(LDLIBS_$@))
DIST_SOURCES = $(ntpdc_SOURCES)
HEADERS = $(noinst_HEADERS)

DIST_COMMON = README $(noinst_HEADERS) Makefile.am Makefile.in
SOURCES = $(ntpdc_SOURCES)

all: all-am

.SUFFIXES:
.SUFFIXES: .c .o .obj
$(srcdir)/Makefile.in:  Makefile.am  $(top_srcdir)/configure.in $(ACLOCAL_M4)
	cd $(top_srcdir) && \
	  $(AUTOMAKE) --gnu  ntpdc/Makefile
Makefile:  $(srcdir)/Makefile.in  $(top_builddir)/config.status
	cd $(top_builddir) && \
	  CONFIG_HEADERS= CONFIG_LINKS= \
	  CONFIG_FILES=$(subdir)/$@ $(SHELL) ./config.status
install-binPROGRAMS: $(bin_PROGRAMS)
	@$(NORMAL_INSTALL)
	$(mkinstalldirs) $(DESTDIR)$(bindir)
	@list='$(bin_PROGRAMS)'; for p in $$list; do \
	  p1=`echo $$p|sed 's/$(EXEEXT)$$//'`; \
	  if test -f $$p \
	  ; then \
	    f=`echo $$p1|sed '$(transform);s/$$/$(EXEEXT)/'`; \
	   echo " $(INSTALL_PROGRAM_ENV) $(INSTALL_PROGRAM) $$p $(DESTDIR)$(bindir)/$$f"; \
	   $(INSTALL_PROGRAM_ENV) $(INSTALL_PROGRAM) $$p $(DESTDIR)$(bindir)/$$f; \
	  else :; fi; \
	done

uninstall-binPROGRAMS:
	@$(NORMAL_UNINSTALL)
	@list='$(bin_PROGRAMS)'; for p in $$list; do \
	  f=`echo $$p|sed 's/$(EXEEXT)$$//;$(transform);s/$$/$(EXEEXT)/'`; \
	  echo " rm -f $(DESTDIR)$(bindir)/$$f"; \
	  rm -f $(DESTDIR)$(bindir)/$$f; \
	done

clean-binPROGRAMS:
	-test -z "$(bin_PROGRAMS)" || rm -f $(bin_PROGRAMS)
ntpdc$(EXEEXT): $(ntpdc_OBJECTS) $(ntpdc_DEPENDENCIES) 
	@rm -f ntpdc$(EXEEXT)
	$(LINK) $(ntpdc_LDFLAGS) $(ntpdc_OBJECTS) $(ntpdc_LDADD) $(LIBS)

mostlyclean-compile:
	-rm -f *.$(OBJEXT) core *.core

distclean-compile:
	-rm -f *.tab.c

ANSI2KNR = ../util/ansi2knr
../util/ansi2knr:
	cd ../util && $(MAKE) $(AM_MAKEFLAGS) ansi2knr

mostlyclean-kr:
	-rm -f *_.c

include $(DEPDIR)/ntpdc$U.Po
include $(DEPDIR)/ntpdc_ops$U.Po

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
ntpdc_.c: ntpdc.c $(ANSI2KNR)
	$(CPP) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(CPPFLAGS) `if test -f $(srcdir)/ntpdc.c; then echo $(srcdir)/ntpdc.c; else echo ntpdc.c; fi` | sed 's/^# \([0-9]\)/#line \1/' | $(ANSI2KNR) > ntpdc_.c || rm -f ntpdc_.c
ntpdc_ops_.c: ntpdc_ops.c $(ANSI2KNR)
	$(CPP) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(CPPFLAGS) `if test -f $(srcdir)/ntpdc_ops.c; then echo $(srcdir)/ntpdc_ops.c; else echo ntpdc_ops.c; fi` | sed 's/^# \([0-9]\)/#line \1/' | $(ANSI2KNR) > ntpdc_ops_.c || rm -f ntpdc_ops_.c
ntpdc_.$(OBJEXT) ntpdc_ops_.$(OBJEXT) : $(ANSI2KNR)
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
check: check-am
all-am: Makefile $(PROGRAMS) $(HEADERS)

installdirs:
	$(mkinstalldirs) $(DESTDIR)$(bindir)

romfs:
	$(ROMFSINST) -e CONFIG_USER_NTPD_NTPDC /bin/ntpdc

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
	-test -z "$(DISTCLEANFILES)" || rm -f $(DISTCLEANFILES)

maintainer-clean-generic:
	@echo "This command is intended for maintainers to use"
	@echo "it deletes files that may require special tools to rebuild."
clean: clean-am

clean-am: clean-binPROGRAMS clean-generic mostlyclean-am

distclean: distclean-am

distclean-am: clean-am distclean-compile distclean-depend \
	distclean-generic distclean-tags

dvi: dvi-am

dvi-am:

info: info-am

info-am:

install-data-am:

install-exec-am: install-binPROGRAMS

install-info: install-info-am

install-man:

installcheck-am:

maintainer-clean: maintainer-clean-am

maintainer-clean-am: distclean-am maintainer-clean-generic

mostlyclean: mostlyclean-am

mostlyclean-am: mostlyclean-compile mostlyclean-generic mostlyclean-kr

uninstall-am: uninstall-binPROGRAMS uninstall-info-am

.PHONY: GTAGS all all-am check check-am clean clean-binPROGRAMS \
	clean-generic distclean distclean-compile distclean-depend \
	distclean-generic distclean-tags distdir dvi dvi-am info \
	info-am install install-am install-binPROGRAMS install-data \
	install-data-am install-exec install-exec-am install-info \
	install-info-am install-man install-strip installcheck \
	installcheck-am installdirs maintainer-clean \
	maintainer-clean-generic mostlyclean mostlyclean-compile \
	mostlyclean-generic mostlyclean-kr tags uninstall uninstall-am \
	uninstall-binPROGRAMS uninstall-info-am


$(PROGRAMS): $(LDADD)

../libntp/libntp.a:
	cd ../libntp && $(MAKE)

version.o: $(ntpdc_OBJECTS) ../libntp/libntp.a  Makefile
	env CSET=`cat $(top_srcdir)/version` $(top_builddir)/scripts/mkver ntpdc
	$(COMPILE) -c version.c
# Tell versions [3.59,3.63) of GNU make to not export all variables.
# Otherwise a system limit (for SysV at least) may be exceeded.
.NOEXPORT:
