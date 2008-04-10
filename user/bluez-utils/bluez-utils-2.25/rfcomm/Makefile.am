
confdir = $(sysconfdir)/bluetooth

conf_DATA = rfcomm.conf

bin_PROGRAMS = rfcomm

rfcomm_SOURCES = main.c parser.h parser.y lexer.l kword.h kword.c
rfcomm_LDADD = @BLUEZ_LIBS@

kword.o lexer.o: parser.h

AM_CFLAGS = @BLUEZ_CFLAGS@

man_MANS = rfcomm.1

AM_YFLAGS = -d

CLEANFILES = lexer.c parser.c parser.h

EXTRA_DIST = $(man_MANS) $(conf_DATA)

MAINTAINERCLEANFILES = Makefile.in
