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
#AUTOMAKE_OPTIONS = ../util/ansi2knr

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

noinst_LIBRARIES = 
EXTRA_LIBRARIES = librsaref.a
CLEANFILES = $(EXTRA_LIBRARIES)


# NOTES:
# don't use RSAREF's global.h - we use ours.
nodist_librsaref_a_SOURCES = \
	desc.c \
	md2c.c \
	md5c.c \
	nn.c \
	prime.c \
	r_dh.c \
	r_encode.c \
	r_enhanc.c \
	r_keygen.c \
	r_random.c \
	r_stdlib.c \
	rsa.c \
	des.h \
	md2.h \
	md5.h \
	nn.h \
	prime.h \
	r_random.h \
	rsa.h \
	rsaref.h 


librsaref_a_LIBADD = 
librsaref_a_DEPENDENCIES = $(librsaref_a_LIBADD)

BUILT_SOURCES = $(nodist_librsaref_a_SOURCES)
INCLUDES = -I$(top_srcdir)/include
ETAGS_ARGS = Makefile.am

DISTCLEANFILES = $(nodist_librsaref_a_SOURCES) stamp-rsaref
subdir = librsaref
mkinstalldirs = $(SHELL) $(top_srcdir)/mkinstalldirs
CONFIG_HEADER = $(top_builddir)/config.h
CONFIG_CLEAN_FILES =
LIBRARIES = $(noinst_LIBRARIES)

librsaref_a_AR = $(AR) cru
nodist_librsaref_a_OBJECTS = desc.$(OBJEXT) md2c.$(OBJEXT) \
	md5c.$(OBJEXT) nn.$(OBJEXT) prime.$(OBJEXT) r_dh.$(OBJEXT) \
	r_encode.$(OBJEXT) r_enhanc.$(OBJEXT) r_keygen.$(OBJEXT) \
	r_random.$(OBJEXT) r_stdlib.$(OBJEXT) rsa.$(OBJEXT)
librsaref_a_OBJECTS = $(nodist_librsaref_a_OBJECTS)

DEFS = -DHAVE_CONFIG_H
DEFAULT_INCLUDES =  -I. -I$(srcdir) -I$(top_builddir)
CPPFLAGS = 
#LDFLAGS = 
LIBS = 
depcomp = $(SHELL) $(top_srcdir)/depcomp
DEP_FILES = $(DEPDIR)/desc.Po $(DEPDIR)/md2c.Po \
	$(DEPDIR)/md5c.Po $(DEPDIR)/nn.Po \
	$(DEPDIR)/prime.Po $(DEPDIR)/r_dh.Po \
	$(DEPDIR)/r_encode.Po $(DEPDIR)/r_enhanc.Po \
	$(DEPDIR)/r_keygen.Po $(DEPDIR)/r_random.Po \
	$(DEPDIR)/r_stdlib.Po $(DEPDIR)/rsa.Po
COMPILE = $(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) \
	$(CPPFLAGS) $(AM_CFLAGS) $(CFLAGS)
CCLD = $(CC)
LINK = $(CCLD) $(AM_CFLAGS) $(AM_LDFLAGS) $(LDFLAGS) -o $@
LIBS += $(LDLIBS$(LDLIBS_$@))
DIST_SOURCES =
DIST_COMMON = Makefile.am Makefile.in
SOURCES = $(nodist_librsaref_a_SOURCES)

all: $(BUILT_SOURCES)
	$(MAKE) $(AM_MAKEFLAGS) all-am

.SUFFIXES:
.SUFFIXES: .c .o .obj
$(srcdir)/Makefile.in:  Makefile.am  $(top_srcdir)/configure.in $(ACLOCAL_M4)
	cd $(top_srcdir) && \
	  $(AUTOMAKE) --gnu  librsaref/Makefile
Makefile:  $(srcdir)/Makefile.in  $(top_builddir)/config.status
	cd $(top_builddir) && \
	  CONFIG_HEADERS= CONFIG_LINKS= \
	  CONFIG_FILES=$(subdir)/$@ $(SHELL) ./config.status

AR = ar

clean-noinstLIBRARIES:
	-test -z "$(noinst_LIBRARIES)" || rm -f $(noinst_LIBRARIES)
librsaref.a: $(librsaref_a_OBJECTS) $(librsaref_a_DEPENDENCIES) 
	-rm -f librsaref.a
	$(librsaref_a_AR) librsaref.a $(librsaref_a_OBJECTS) $(librsaref_a_LIBADD)
	$(RANLIB) librsaref.a

mostlyclean-compile:
	-rm -f *.$(OBJEXT) core *.core

distclean-compile:
	-rm -f *.tab.c

include $(DEPDIR)/desc.Po
include $(DEPDIR)/md2c.Po
include $(DEPDIR)/md5c.Po
include $(DEPDIR)/nn.Po
include $(DEPDIR)/prime.Po
include $(DEPDIR)/r_dh.Po
include $(DEPDIR)/r_encode.Po
include $(DEPDIR)/r_enhanc.Po
include $(DEPDIR)/r_keygen.Po
include $(DEPDIR)/r_random.Po
include $(DEPDIR)/r_stdlib.Po
include $(DEPDIR)/rsa.Po

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
	-test -z "$(CLEANFILES)" || rm -f $(CLEANFILES)

distclean-generic:
	-rm -f Makefile $(CONFIG_CLEAN_FILES) stamp-h stamp-h[0-9]*
	-test -z "$(DISTCLEANFILES)" || rm -f $(DISTCLEANFILES)

maintainer-clean-generic:
	@echo "This command is intended for maintainers to use"
	@echo "it deletes files that may require special tools to rebuild."
	-test -z "$(BUILT_SOURCES)" || rm -f $(BUILT_SOURCES)
clean: clean-am

clean-am: clean-generic clean-noinstLIBRARIES mostlyclean-am

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

.PHONY: GTAGS all all-am check check-am clean clean-generic \
	clean-noinstLIBRARIES distclean distclean-compile \
	distclean-depend distclean-generic distclean-tags distdir dvi \
	dvi-am info info-am install install-am install-data \
	install-data-am install-exec install-exec-am install-info \
	install-info-am install-man install-strip installcheck \
	installcheck-am installdirs maintainer-clean \
	maintainer-clean-generic mostlyclean mostlyclean-compile \
	mostlyclean-generic tags uninstall uninstall-am \
	uninstall-info-am


#EXTRA_DIST = 

$(nodist_librsaref_a_SOURCES): stamp-rsaref

stamp-rsaref:
	@rm -f stamp-rsaref stamp-rsarefT
	@echo timestamp > stamp-rsarefT 2> /dev/null
	for i in $(nodist_librsaref_a_SOURCES); do \
	    case "" in \
	     '') touch $$i ;; \
	     *) case "$$i" in \
		 *.h) r_dst=$(srcdir)/$$i ;; \
		 *)   r_dst=$$i ;; \
		esac ; \
	 	cmp -s $${r_dst} $(srcdir)/..//source/$$i 2>/dev/null \
			|| cp $(srcdir)/..//source/$$i $${r_dst} ;; \
	    esac ; \
	done
	@echo timestamp > stamp-rsarefT 2> /dev/null
	@mv stamp-rsarefT stamp-rsaref
# Tell versions [3.59,3.63) of GNU make to not export all variables.
# Otherwise a system limit (for SysV at least) may be exceeded.
.NOEXPORT:
