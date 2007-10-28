## $Id: Makefile.am,v 5.14 2006/05/06 09:40:07 lirc Exp $

## Process this file with automake to produce Makefile.in 

INCLUDES = -I$(top_srcdir)

EXTRA_PROGRAMS = smode2 xmode2 irxevent
bin_PROGRAMS = irw irpty irexec ircat mode2 irsend \
	lircrcd \
	@vga_progs@ @x_progs@

AM_CPPFLAGS = @X_CFLAGS@

## simple programs
irw_SOURCES = irw.c
irpty_SOURCES = irpty.c
irpty_DEPENDENCIES = liblirc_client.la
irpty_LDADD = liblirc_client.la @forkpty@
irexec_SOURCES = irexec.c
irexec_DEPENDENCIES = liblirc_client.la
irexec_LDADD = liblirc_client.la @daemon@
ircat_SOURCES = ircat.c
ircat_DEPENDENCIES = liblirc_client.la
ircat_LDADD = liblirc_client.la
mode2_SOURCES = mode2.c
irsend_SOURCES = irsend.c

## vga programs
smode2_SOURCES = smode2.c
smode2_LDADD = -lvga -lvgagl

## x programs
irxevent_SOURCES = irxevent.c
irxevent_LDADD = @X_LIBS@ @X_PRE_LIBS@ -lX11 @X_EXTRA_LIBS@ liblirc_client.la
irxevent_DEPENDENCIES = liblirc_client.la
xmode2_SOURCES = xmode2.c
xmode2_LDADD = @X_LIBS@ @X_PRE_LIBS@ -lX11 @X_EXTRA_LIBS@

## lircrcd

lircrcd_SOURCES = lircrcd.c
lircrcd_DEPENDENCIES = liblirc_client.la
lircrcd_LDADD = liblirc_client.la

## libraries
lircincludedir = $(includedir)/lirc

lib_LTLIBRARIES = liblirc_client.la
liblirc_client_la_SOURCES = lirc_client.c lirc_client.h
liblirc_client_la_LDFLAGS = -version-info 2:0:2

lircinclude_HEADERS = lirc_client.h

CLEANFILES = *~
