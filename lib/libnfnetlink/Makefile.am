AUTOMAKE_OPTIONS = foreign dist-bzip2 1.6

EXTRA_DIST = $(man_MANS) debian

SUBDIRS = src include
DIST_SUBDIRS = src include

man_MANS = #nfnetlink.3

$(OBJECTS): libtool
libtool: $(LIBTOOL_DEPS)
	$(SHELL) ./config.status --recheck

dist-hook:
	rm -rf `find $(distdir)/debian -name .svn`
