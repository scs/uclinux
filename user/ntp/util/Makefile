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



#AUTOMAKE_OPTIONS = ../ansi2knr no-dependencies

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

AUTOMAKE_OPTIONS = ansi2knr
bin_PROGRAMS = ntptime tickadj  ntp-genkeys
EXTRA_PROGRAMS = byteorder hist jitter kern longsize ntptime \
precision sht testrs6000 tickadj timetrim


ntp_genkeys_LDADD = ../ntpd/ntp_config$U.o ../libntp/libntp.a $(LIBRSAREF)
ntp_genkeys_DEPENDENCIES = ../ntpd/ntp_config$U.o ../libntp/libntp.a $(LIBRSAREF)

INCLUDES = -I$(top_srcdir)/include -I$(top_srcdir)/librsaref
# LDADD might need RESLIB and ADJLIB
LDADD = ../libntp/libntp.a
#EXTRA_DIST = README TAGS
EXTRA_DIST = 
ETAGS_ARGS = Makefile.am
subdir = util
mkinstalldirs = $(SHELL) $(top_srcdir)/mkinstalldirs
CONFIG_HEADER = $(top_builddir)/config.h
CONFIG_CLEAN_FILES =
EXTRA_PROGRAMS = byteorder$(EXEEXT) hist$(EXEEXT) jitter$(EXEEXT) \
	kern$(EXEEXT) longsize$(EXEEXT) ntptime$(EXEEXT) \
	precision$(EXEEXT) sht$(EXEEXT) testrs6000$(EXEEXT) \
	tickadj$(EXEEXT) timetrim$(EXEEXT)
bin_PROGRAMS = ntptime tickadj  \
	ntp-genkeys$(EXEEXT)
PROGRAMS = $(bin_PROGRAMS)

byteorder_SOURCES = byteorder.c
byteorder_OBJECTS = byteorder$U.$(OBJEXT)
byteorder_LDADD = $(LDADD)
byteorder_DEPENDENCIES = ../libntp/libntp.a
byteorder_LDFLAGS =
hist_SOURCES = hist.c
hist_OBJECTS = hist$U.$(OBJEXT)
hist_LDADD = $(LDADD)
hist_DEPENDENCIES = ../libntp/libntp.a
hist_LDFLAGS =
jitter_SOURCES = jitter.c
jitter_OBJECTS = jitter$U.$(OBJEXT)
jitter_LDADD = $(LDADD)
jitter_DEPENDENCIES = ../libntp/libntp.a
jitter_LDFLAGS =
kern_SOURCES = kern.c
kern_OBJECTS = kern$U.$(OBJEXT)
kern_LDADD = $(LDADD)
kern_DEPENDENCIES = ../libntp/libntp.a
kern_LDFLAGS =
longsize_SOURCES = longsize.c
longsize_OBJECTS = longsize$U.$(OBJEXT)
longsize_LDADD = $(LDADD)
longsize_DEPENDENCIES = ../libntp/libntp.a
longsize_LDFLAGS =
ntp_genkeys_SOURCES = ntp-genkeys.c
ntp_genkeys_OBJECTS = ntp-genkeys$U.$(OBJEXT)
ntp_genkeys_LDFLAGS =
ntptime_SOURCES = ntptime.c
ntptime_OBJECTS = ntptime$U.$(OBJEXT)
ntptime_LDADD = $(LDADD)
ntptime_DEPENDENCIES = ../libntp/libntp.a
ntptime_LDFLAGS =
precision_SOURCES = precision.c
precision_OBJECTS = precision$U.$(OBJEXT)
precision_LDADD = $(LDADD)
precision_DEPENDENCIES = ../libntp/libntp.a
precision_LDFLAGS =
sht_SOURCES = sht.c
sht_OBJECTS = sht$U.$(OBJEXT)
sht_LDADD = $(LDADD)
sht_DEPENDENCIES = ../libntp/libntp.a
sht_LDFLAGS =
testrs6000_SOURCES = testrs6000.c
testrs6000_OBJECTS = testrs6000$U.$(OBJEXT)
testrs6000_LDADD = $(LDADD)
testrs6000_DEPENDENCIES = ../libntp/libntp.a
testrs6000_LDFLAGS =
tickadj_SOURCES = tickadj.c
tickadj_OBJECTS = tickadj$U.$(OBJEXT)
tickadj_LDADD = $(LDADD)
tickadj_DEPENDENCIES = ../libntp/libntp.a
tickadj_LDFLAGS =
timetrim_SOURCES = timetrim.c
timetrim_OBJECTS = timetrim$U.$(OBJEXT)
timetrim_LDADD = $(LDADD)
timetrim_DEPENDENCIES = ../libntp/libntp.a
timetrim_LDFLAGS =

DEFS = -DHAVE_CONFIG_H
DEFAULT_INCLUDES =  -I. -I$(srcdir) -I$(top_builddir)
CPPFLAGS = 
#LDFLAGS = 
LIBS = 
depcomp = $(SHELL) $(top_srcdir)/depcomp
DEP_FILES = $(DEPDIR)/byteorder$U.Po $(DEPDIR)/hist$U.Po \
	$(DEPDIR)/jitter$U.Po $(DEPDIR)/kern$U.Po \
	$(DEPDIR)/longsize$U.Po $(DEPDIR)/ntp-genkeys$U.Po \
	$(DEPDIR)/ntptime$U.Po $(DEPDIR)/precision$U.Po \
	$(DEPDIR)/sht$U.Po $(DEPDIR)/testrs6000$U.Po \
	$(DEPDIR)/tickadj$U.Po $(DEPDIR)/timetrim$U.Po
COMPILE = $(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) \
	$(CPPFLAGS) $(AM_CFLAGS) $(CFLAGS)
CCLD = $(CC)
LINK = $(CCLD) $(AM_CFLAGS) $(AM_LDFLAGS) $(LDFLAGS) -o $@
LIBS += $(LDLIBS$(LDLIBS_$@))
DIST_SOURCES = byteorder.c hist.c jitter.c kern.c longsize.c \
	ntp-genkeys.c ntptime.c precision.c sht.c testrs6000.c \
	tickadj.c timetrim.c
DIST_COMMON = README Makefile.am Makefile.in ansi2knr.1 ansi2knr.c
SOURCES = byteorder.c hist.c jitter.c kern.c longsize.c ntp-genkeys.c ntptime.c precision.c sht.c testrs6000.c tickadj.c timetrim.c

all: all-am

.SUFFIXES:
.SUFFIXES: .c .o .obj
$(srcdir)/Makefile.in:  Makefile.am  $(top_srcdir)/configure.in $(ACLOCAL_M4)
	cd $(top_srcdir) && \
	  $(AUTOMAKE) --gnu  util/Makefile
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
byteorder$(EXEEXT): $(byteorder_OBJECTS) $(byteorder_DEPENDENCIES) 
	@rm -f byteorder$(EXEEXT)
	$(LINK) $(byteorder_LDFLAGS) $(byteorder_OBJECTS) $(byteorder_LDADD) $(LIBS)
hist$(EXEEXT): $(hist_OBJECTS) $(hist_DEPENDENCIES) 
	@rm -f hist$(EXEEXT)
	$(LINK) $(hist_LDFLAGS) $(hist_OBJECTS) $(hist_LDADD) $(LIBS)
jitter$(EXEEXT): $(jitter_OBJECTS) $(jitter_DEPENDENCIES) 
	@rm -f jitter$(EXEEXT)
	$(LINK) $(jitter_LDFLAGS) $(jitter_OBJECTS) $(jitter_LDADD) $(LIBS)
kern$(EXEEXT): $(kern_OBJECTS) $(kern_DEPENDENCIES) 
	@rm -f kern$(EXEEXT)
	$(LINK) $(kern_LDFLAGS) $(kern_OBJECTS) $(kern_LDADD) $(LIBS)
longsize$(EXEEXT): $(longsize_OBJECTS) $(longsize_DEPENDENCIES) 
	@rm -f longsize$(EXEEXT)
	$(LINK) $(longsize_LDFLAGS) $(longsize_OBJECTS) $(longsize_LDADD) $(LIBS)
ntp-genkeys$(EXEEXT): $(ntp_genkeys_OBJECTS) $(ntp_genkeys_DEPENDENCIES) 
	@rm -f ntp-genkeys$(EXEEXT)
	$(LINK) $(ntp_genkeys_LDFLAGS) $(ntp_genkeys_OBJECTS) $(ntp_genkeys_LDADD) $(LIBS)
ntptime$(EXEEXT): $(ntptime_OBJECTS) $(ntptime_DEPENDENCIES) 
	@rm -f ntptime$(EXEEXT)
	$(LINK) $(ntptime_LDFLAGS) $(ntptime_OBJECTS) $(ntptime_LDADD) $(LIBS)
precision$(EXEEXT): $(precision_OBJECTS) $(precision_DEPENDENCIES) 
	@rm -f precision$(EXEEXT)
	$(LINK) $(precision_LDFLAGS) $(precision_OBJECTS) $(precision_LDADD) $(LIBS)
sht$(EXEEXT): $(sht_OBJECTS) $(sht_DEPENDENCIES) 
	@rm -f sht$(EXEEXT)
	$(LINK) $(sht_LDFLAGS) $(sht_OBJECTS) $(sht_LDADD) $(LIBS)
testrs6000$(EXEEXT): $(testrs6000_OBJECTS) $(testrs6000_DEPENDENCIES) 
	@rm -f testrs6000$(EXEEXT)
	$(LINK) $(testrs6000_LDFLAGS) $(testrs6000_OBJECTS) $(testrs6000_LDADD) $(LIBS)
tickadj$(EXEEXT): $(tickadj_OBJECTS) $(tickadj_DEPENDENCIES) 
	@rm -f tickadj$(EXEEXT)
	$(LINK) $(tickadj_LDFLAGS) $(tickadj_OBJECTS) $(tickadj_LDADD) $(LIBS)
timetrim$(EXEEXT): $(timetrim_OBJECTS) $(timetrim_DEPENDENCIES) 
	@rm -f timetrim$(EXEEXT)
	$(LINK) $(timetrim_LDFLAGS) $(timetrim_OBJECTS) $(timetrim_LDADD) $(LIBS)

mostlyclean-compile:
	-rm -f *.$(OBJEXT) core *.core

distclean-compile:
	-rm -f *.tab.c

ANSI2KNR = 
ansi2knr: ansi2knr.$(OBJEXT)
	$(LINK) ansi2knr.$(OBJEXT) $(LIBS)
ansi2knr.$(OBJEXT): $(CONFIG_HEADER)

clean-krextra:
	-rm -f ansi2knr

mostlyclean-kr:
	-rm -f *_.c

include $(DEPDIR)/byteorder$U.Po
include $(DEPDIR)/hist$U.Po
include $(DEPDIR)/jitter$U.Po
include $(DEPDIR)/kern$U.Po
include $(DEPDIR)/longsize$U.Po
include $(DEPDIR)/ntp-genkeys$U.Po
include $(DEPDIR)/ntptime$U.Po
include $(DEPDIR)/precision$U.Po
include $(DEPDIR)/sht$U.Po
include $(DEPDIR)/testrs6000$U.Po
include $(DEPDIR)/tickadj$U.Po
include $(DEPDIR)/timetrim$U.Po

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
byteorder_.c: byteorder.c $(ANSI2KNR)
	$(CPP) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(CPPFLAGS) `if test -f $(srcdir)/byteorder.c; then echo $(srcdir)/byteorder.c; else echo byteorder.c; fi` | sed 's/^# \([0-9]\)/#line \1/' | $(ANSI2KNR) > byteorder_.c || rm -f byteorder_.c
hist_.c: hist.c $(ANSI2KNR)
	$(CPP) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(CPPFLAGS) `if test -f $(srcdir)/hist.c; then echo $(srcdir)/hist.c; else echo hist.c; fi` | sed 's/^# \([0-9]\)/#line \1/' | $(ANSI2KNR) > hist_.c || rm -f hist_.c
jitter_.c: jitter.c $(ANSI2KNR)
	$(CPP) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(CPPFLAGS) `if test -f $(srcdir)/jitter.c; then echo $(srcdir)/jitter.c; else echo jitter.c; fi` | sed 's/^# \([0-9]\)/#line \1/' | $(ANSI2KNR) > jitter_.c || rm -f jitter_.c
kern_.c: kern.c $(ANSI2KNR)
	$(CPP) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(CPPFLAGS) `if test -f $(srcdir)/kern.c; then echo $(srcdir)/kern.c; else echo kern.c; fi` | sed 's/^# \([0-9]\)/#line \1/' | $(ANSI2KNR) > kern_.c || rm -f kern_.c
longsize_.c: longsize.c $(ANSI2KNR)
	$(CPP) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(CPPFLAGS) `if test -f $(srcdir)/longsize.c; then echo $(srcdir)/longsize.c; else echo longsize.c; fi` | sed 's/^# \([0-9]\)/#line \1/' | $(ANSI2KNR) > longsize_.c || rm -f longsize_.c
ntp-genkeys_.c: ntp-genkeys.c $(ANSI2KNR)
	$(CPP) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(CPPFLAGS) `if test -f $(srcdir)/ntp-genkeys.c; then echo $(srcdir)/ntp-genkeys.c; else echo ntp-genkeys.c; fi` | sed 's/^# \([0-9]\)/#line \1/' | $(ANSI2KNR) > ntp-genkeys_.c || rm -f ntp-genkeys_.c
ntptime_.c: ntptime.c $(ANSI2KNR)
	$(CPP) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(CPPFLAGS) `if test -f $(srcdir)/ntptime.c; then echo $(srcdir)/ntptime.c; else echo ntptime.c; fi` | sed 's/^# \([0-9]\)/#line \1/' | $(ANSI2KNR) > ntptime_.c || rm -f ntptime_.c
precision_.c: precision.c $(ANSI2KNR)
	$(CPP) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(CPPFLAGS) `if test -f $(srcdir)/precision.c; then echo $(srcdir)/precision.c; else echo precision.c; fi` | sed 's/^# \([0-9]\)/#line \1/' | $(ANSI2KNR) > precision_.c || rm -f precision_.c
sht_.c: sht.c $(ANSI2KNR)
	$(CPP) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(CPPFLAGS) `if test -f $(srcdir)/sht.c; then echo $(srcdir)/sht.c; else echo sht.c; fi` | sed 's/^# \([0-9]\)/#line \1/' | $(ANSI2KNR) > sht_.c || rm -f sht_.c
testrs6000_.c: testrs6000.c $(ANSI2KNR)
	$(CPP) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(CPPFLAGS) `if test -f $(srcdir)/testrs6000.c; then echo $(srcdir)/testrs6000.c; else echo testrs6000.c; fi` | sed 's/^# \([0-9]\)/#line \1/' | $(ANSI2KNR) > testrs6000_.c || rm -f testrs6000_.c
tickadj_.c: tickadj.c $(ANSI2KNR)
	$(CPP) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(CPPFLAGS) `if test -f $(srcdir)/tickadj.c; then echo $(srcdir)/tickadj.c; else echo tickadj.c; fi` | sed 's/^# \([0-9]\)/#line \1/' | $(ANSI2KNR) > tickadj_.c || rm -f tickadj_.c
timetrim_.c: timetrim.c $(ANSI2KNR)
	$(CPP) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) $(CPPFLAGS) `if test -f $(srcdir)/timetrim.c; then echo $(srcdir)/timetrim.c; else echo timetrim.c; fi` | sed 's/^# \([0-9]\)/#line \1/' | $(ANSI2KNR) > timetrim_.c || rm -f timetrim_.c
byteorder_.$(OBJEXT) hist_.$(OBJEXT) jitter_.$(OBJEXT) kern_.$(OBJEXT) \
longsize_.$(OBJEXT) ntp-genkeys_.$(OBJEXT) ntptime_.$(OBJEXT) \
precision_.$(OBJEXT) sht_.$(OBJEXT) testrs6000_.$(OBJEXT) \
tickadj_.$(OBJEXT) timetrim_.$(OBJEXT) : $(ANSI2KNR)
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
all-am: Makefile $(ANSI2KNR) $(PROGRAMS)

installdirs:
	$(mkinstalldirs) $(DESTDIR)$(bindir)

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

clean-am: clean-binPROGRAMS clean-generic clean-krextra mostlyclean-am

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
	clean-generic clean-krextra distclean distclean-compile \
	distclean-depend distclean-generic distclean-tags distdir dvi \
	dvi-am info info-am install install-am install-binPROGRAMS \
	install-data install-data-am install-exec install-exec-am \
	install-info install-info-am install-man install-strip \
	installcheck installcheck-am installdirs maintainer-clean \
	maintainer-clean-generic mostlyclean mostlyclean-compile \
	mostlyclean-generic mostlyclean-kr tags uninstall uninstall-am \
	uninstall-binPROGRAMS uninstall-info-am


../libntp/libntp.a:
	cd ../libntp && $(MAKE)

kern.o: kern.c
	$(COMPILE) -DHAVE_TIMEX_H -c kern.c
# Tell versions [3.59,3.63) of GNU make to not export all variables.
# Otherwise a system limit (for SysV at least) may be exceeded.
.NOEXPORT:
