SUBDIRS = include vmutils vm adapter gcic tkimg scope nucleus skins

EXTRA_DIST = doc

dist-hook:
#	rm -fr $(distdir)/include/xenomai $(distdir)/include/asm
	find $(distdir)/doc $(distdir)/include -name .svn -depth -exec rm -fr \{\} \;
