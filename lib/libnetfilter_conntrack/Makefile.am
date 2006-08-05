include $(top_srcdir)/Make_global.am

AUTOMAKE_OPTIONS = foreign dist-bzip2 1.6

SUBDIRS	= include src l3extensions extensions utils
LINKOPTS = -lnfnetlink

man_MANS = #nfnetlink_conntrack.3 nfnetlink_conntrack.7

EXTRA_DIST = Make_global.am debian
dist-hook:
	rm -rf `find $(distdir)/debian -name .svn`

$(OBJECTS): libtool
libtool: $(LIBTOOL_DEPS)
	$(SHELL) ./config.status --recheck
