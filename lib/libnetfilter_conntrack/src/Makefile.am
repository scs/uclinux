include $(top_srcdir)/Make_global.am

#AUTOMAKE_OPTIONS = no-dependencies foreign

#EXTRA_DIST = $(man_MANS) acinclude.m4

AM_CFLAGS=-fPIC -Wall
LIBS=

lib_LTLIBRARIES = libnetfilter_conntrack.la 

libnetfilter_conntrack_la_LDFLAGS = -Wc,-nostartfiles	\
				    -version-info $(LIBVERSION)
libnetfilter_conntrack_la_SOURCES = libnetfilter_conntrack.c 
libnetfilter_conntrack_la_LIBADD = -lnfnetlink
