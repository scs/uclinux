## Process this file with automake to produce Makefile.in
# Copyright (C) 2002, 2003, 2004, 2005, 2006, 2007 Simon Josefsson.
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

ACLOCAL_AMFLAGS = -I m4 -I gl/m4

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libgsasl.pc

SUBDIRS = po gl tests

# Plugins:
if EXTERNAL
SUBDIRS += external
endif

if ANONYMOUS
SUBDIRS += anonymous
endif

if PLAIN
SUBDIRS += plain
endif

if LOGIN
SUBDIRS += login
endif

if CRAM_MD5
SUBDIRS += cram-md5
endif

if DIGEST_MD5
SUBDIRS += digest-md5
endif

if NTLM
SUBDIRS += ntlm
endif

if GSSAPI
SUBDIRS += gssapi
endif			

if GS2
SUBDIRS += gs2
endif			

if SECURID
SUBDIRS += securid
endif			

if KERBEROS_V5
SUBDIRS += kerberos_v5
endif

SUBDIRS += src

# Maintainer targets

update-po: refresh-po
	cg-add `ls po/*.po | grep -v quot.po`
	cg-commit -m "Sync with TP." po/LINGUAS `ls po/*.po | grep -v quot.po`

ChangeLog:
	git log --pretty --numstat --summary | git2cl > ChangeLog
	cat ../.cvscopying >> ChangeLog

htmldir = ../../www-gsasl

release:
	rm -f ChangeLog
	$(MAKE) ChangeLog distcheck
	git commit -m Generated. ChangeLog
	gnupload --to alpha.gnu.org:gsasl $(distdir).tar.gz
	cp -v $(distdir).tar.gz{,.sig} $(htmldir)/releases/
	cd $(htmldir) && cvs add -kb releases/$(distdir).tar.gz{,.sig} && \
		cvs commit -m "Update." releases/
