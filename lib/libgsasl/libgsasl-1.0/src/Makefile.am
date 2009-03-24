# Copyright (C) 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009 Simon Josefsson
#
# This file is part of GNU SASL Library.
#
# GNU SASL Library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public License
# as published by the Free Software Foundation; either version 2.1 of
# the License, or (at your option) any later version.
#
# GNU SASL Library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with GNU SASL Library; if not, write to the Free
# Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
# MA 02110-1301, USA.

lib_LTLIBRARIES = libgsasl.la

AM_CFLAGS = $(WARN_CFLAGS)
AM_CPPFLAGS = -I$(srcdir)/../gl -I../gl -I$(srcdir)/..
DEFS = -DLOCALEDIR=\"$(datadir)/locale\" @DEFS@

EXTRA_DIST = doxygen.c

include_HEADERS = gsasl.h gsasl-mech.h gsasl-compat.h

libgsasl_la_LDFLAGS = -version-info $(LT_CURRENT):$(LT_REVISION):$(LT_AGE) \
	-export-symbols-regex '^(gsasl|GSASL).*' -no-undefined
libgsasl_la_LIBADD = ../gl/libgl.la @LTLIBINTL@ @LTLIBIDN@
libgsasl_la_SOURCES = internal.h \
	init.c done.c register.c error.c version.c \
	callback.c property.c \
	supportp.c suggest.c listmech.c \
	xstart.c xstep.c xfinish.c xcode.c mechname.c \
	base64.c md5pwd.c crypto.c \
	saslprep.c free.c

if HAVE_LD_OUTPUT_DEF
libgsasl_la_LDFLAGS += -Wl,--output-def,libgsasl-$(SOVERSION).def
defexecdir = $(bindir)
defexec_DATA = libgsasl-$(SOVERSION).def
DISTCLEANFILES = $(defexec_DATA)
endif

if OBSOLETE
libgsasl_la_SOURCES += obsolete.c
endif

# Plugins:
if EXTERNAL
libgsasl_la_LIBADD += ../external/libgsasl-external.la
endif

if ANONYMOUS
libgsasl_la_LIBADD += ../anonymous/libgsasl-anonymous.la
endif

if PLAIN
libgsasl_la_LIBADD += ../plain/libgsasl-plain.la
endif

if LOGIN
libgsasl_la_LIBADD += ../login/libgsasl-login.la
endif

if CRAM_MD5
libgsasl_la_LIBADD += ../cram-md5/libgsasl-cram_md5.la
endif

if DIGEST_MD5
libgsasl_la_LIBADD += ../digest-md5/libgsasl-digest_md5.la
endif

if NTLM
libgsasl_la_LIBADD += ../ntlm/libgsasl-ntlm.la
endif

if GSSAPI
libgsasl_la_LIBADD += ../gssapi/libgsasl-gssapi.la
endif			

if GS2
libgsasl_la_LIBADD += ../gs2/libgsasl-gs2.la
endif			

if SECURID
libgsasl_la_LIBADD += ../securid/libgsasl-securid.la
endif			

if KERBEROS_V5
libgsasl_la_LIBADD += ../kerberos_v5/libgsasl-kerberos_v5.la
endif
