#AUTOMAKE_OPTIONS = no-dependencies foreign

#EXTRA_DIST = $(man_MANS) acinclude.m4

INCLUDES = $(all_includes) -I$(top_srcdir)/include
AM_CFLAGS=-fPIC -Wall
LIBS=

lib_LTLIBRARIES = libnfnetlink.la

libnfnetlink_la_LDFLAGS = -Wc,-nostartfiles
libnfnetlink_la_SOURCES = libnfnetlink.c 
