## $Id: Makefile.am,v 1.7 2006/01/21 17:17:30 lirc Exp $

## Process this file with automake to produce Makefile.in 

man_MANS= irexec.1 ircat.1 irpty.1 irrecord.1 irw.1 irxevent.1 \
	lircd.8 lircmd.8 lircrcd.1 mode2.1 smode2.1 xmode2.1 irsend.1

EXTRA_DIST = $(man_MANS)

%.1 %.8:
	(cd .. && make release-man)

dist-hook: $(man_MANS)

maintainer-clean-local:
	rm -f $(man_MANS)
