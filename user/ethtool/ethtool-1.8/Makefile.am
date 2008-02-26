AM_CFLAGS = -Wall

man_MANS = ethtool.8
EXTRA_DIST = ethtool.8 ethtool.spec.in aclocal.m4 ChangeLog

sbin_PROGRAMS = ethtool
ethtool_SOURCES = de2104x.c ethtool.c ethtool-copy.h ethtool-util.h natsemi.c \
                  e1000.c realtek.c e100.c tg3.c amd8111e.c

dist-hook:
	cp $(top_srcdir)/ethtool.spec $(distdir)
	sed -e 's/^[ 	]\+\*/-/' \
	    -e 's/^[ 	]\+/  /' \
	    -e 's/^\([^ 	-]\)/\* \1/' \
	    -e '/^[ 	]*$$/d' $(top_srcdir)/ChangeLog >> $(distdir)/ethtool.spec
