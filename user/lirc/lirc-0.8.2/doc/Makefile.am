## $Id: Makefile.am,v 1.10 2007/06/09 19:34:20 lirc Exp $

## Process this file with automake to produce Makefile.in 

EXTRA_DIST=lirc.css irxevent.keys lirc.hwdb

SUBDIRS = man

lirc.hwdb:
	touch $@

noinst_PROGRAMS = man2html

release-man: man2html
	./release-man.sh

release-html:
	./release-html.sh

release: release-man release-html

dist-hook: release
	cp -a html images $(distdir)

maintainer-clean-local:
	rm -rf html man-html
