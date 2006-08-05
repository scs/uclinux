AUTOMAKE_OPTIONS = foreign dist-bzip2 1.6

INCLUDES =$(all_includes) -I$(top_srcdir)/include
SUBDIRS	= include src utils
LINKOPTS = -lnfnetlink

EXTRA_DIST = $(man_MANS)

man_MANS = #nfnetlink_log.3 nfnetlink_log.7

$(OBJECTS): libtool
libtool: $(LIBTOOL_DEPS)
	$(SHELL) ./config.status --recheck
