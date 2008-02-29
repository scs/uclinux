## Process this file with automake to produce Makefile.in
# Copyright (C) 2002, 2003, 2004, 2006, 2007, 2008 Simon Josefsson.
#
# This file is part of GNU Libidn.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

AM_CPPFLAGS = -I$(top_srcdir)/lib -I../lib -I$(top_srcdir)/gl -I../gl

dist_lisp_DATA = punycode.el idna.el

bin_PROGRAMS = idn

BUILT_SOURCES = idn_cmd.c idn_cmd.h
idn_SOURCES = idn.c idn.ggo idn_cmd.c idn_cmd.h
DISTCLEANFILES = $(BUILT_SOURCES)
idn_LDADD = ../lib/libidn.la ../gl/libgnu.la $(LTLIBINTL)

localedir = $(datadir)/locale
DEFS = -DLOCALEDIR=\"$(localedir)\" @DEFS@

idn.c: $(BUILT_SOURCES)

idn_cmd.c idn_cmd.h: idn.ggo Makefile.am
	gengetopt --unamed-opts --no-handle-version --no-handle-help \
		--set-package="idn" \
		--input $^ --file-name idn_cmd || \
		test -f idn_cmd.h -a -f idn_cmd.c || \
		cp $(srcdir)/idn_cmd.h $(srcdir)/idn_cmd.h .
	perl -pi -e 's/\[OPTIONS\]/\[OPTION\]/g' idn_cmd.c
	perl -pi -e 's/\[FILES\]/\[STRINGS\]/g' idn_cmd.c
