#
#  $Id: Makefile.am,v 1.2 2005/04/22 17:17:27 bmidgley Exp $
#

noinst_LIBRARIES = libavdtp.a

libavdtp_a_SOURCES = avdtp.h avdtp.c

noinst_PROGRAMS = avtest

avtest_LDADD = @BLUEZ_LIBS@ libavdtp.a -lbluetooth

AM_CFLAGS = @BLUEZ_CFLAGS@

MAINTAINERCLEANFILES = Makefile.in
