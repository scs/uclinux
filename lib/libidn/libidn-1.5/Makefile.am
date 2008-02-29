## Process this file with automake to produce Makefile.in
# Copyright (C) 2002, 2003, 2004, 2005, 2006, 2007, 2008 Simon Josefsson.
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

SUBDIRS = gl lib/gl lib po src doc tests examples java csharp

ACLOCAL_AMFLAGS = -I m4 -I gl/m4 -I lib/gl/m4
DISTCHECK_CONFIGURE_FLAGS = --enable-gtk-doc

EXTRA_DIST = FAQ libc/README libc/getaddrinfo-idn.txt libc/example.c \
	contrib/README contrib/idn-python/README contrib/idn-python/Makefile \
	contrib/idn-python/idn.c contrib/idn-python/test.py \
	contrib/web/idn.php \
	contrib/java/README contrib/java/autogen.sh \
	contrib/java/configure.ac contrib/java/Makefile.am \
	contrib/java/ExampleIDNA.java contrib/java/IDNA.java \
	contrib/java/IDNA.c \
	contrib/doxygen/Doxyfile.in contrib/doxygen/Doxyfile.orig \
	contrib/doxygen/gdoc2doxygen

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libidn.pc

# Maintainer targets

update-po: refresh-po
	git-update-index --add `ls po/*.po | grep -v quot.po` || true && \
	git-commit -m "Sync with TP." po/LINGUAS `ls po/*.po | grep -v quot.po`

ChangeLog:
	git log --pretty --numstat --summary | git2cl > ChangeLog
	cat .cvscopying >> ChangeLog

tag = $(PACKAGE)-`echo $(VERSION) | sed 's/\./-/g'`
htmldir = ../www-$(PACKAGE)

release:
	! git-tag -l $(tag) | grep $(PACKAGE) > /dev/null
	rm -f ChangeLog
	$(MAKE) ChangeLog distcheck
	git commit -m Generated. ChangeLog
	git-tag -u b565716f! -m $(VERSION) $(tag)
	cd doc && env MAKEINFO="makeinfo -I ../examples" \
		      TEXI2DVI="texi2dvi -I ../examples" \
		../build-aux/gendocs.sh --html "--css-include=texinfo.css" \
		-o ../$(htmldir)/manual/ $(PACKAGE) "GNU Libidn"
	cd contrib/doxygen && doxygen && cd ../.. && cp -v contrib/doxygen/html/* $(htmldir)/doxygen/ && cd contrib/doxygen/latex && make refman.pdf && cd ../../../ && cp contrib/doxygen/latex/refman.pdf $(htmldir)/doxygen/$(PACKAGE).pdf
	cp -v $(distdir).tar.gz $(htmldir)/releases/
	cp -v doc/reference/html/*.html doc/reference/html/*.png doc/reference/html/*.devhelp doc/reference/html/*.css $(htmldir)/reference/
	cp -v doc/java/*.html $(htmldir)/javadoc/
	git-push
	git-push --tags
	build-aux/gnupload --to ftp.gnu.org:libidn --to alpha.gnu.org:libidn $(distdir).tar.gz
	cp -v $(distdir).tar.gz.sig $(htmldir)/releases/
	cd $(htmldir) && \
		cvs add -kb releases/$(distdir).tar.gz \
			releases/$(distdir).tar.gz.sig && \
		cvs commit -m "Update." manual/ javadoc/ reference/ \
					doxygen/ releases/
