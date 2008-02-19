## Process this file with automake to produce Makefile.in

INCLUDES = \
	-I$(top_srcdir)\
	-I$(top_srcdir)/coreapi\
	-I$(top_srcdir)/oRTP/include \
	-I$(top_srcdir)/exosip \
	-I$(top_srcdir)/mediastreamer2/include \
	-I$(osip_prefix)/include 



bin_PROGRAMS =  linphonec sipomatic

linphonec_SOURCES = linphonec.c linphonec.h commands.c

linphonec_LDADD = $(top_builddir)/coreapi/liblinphone.la $(READLINE_LIBS)

sipomatic_SOURCES=\
	sipomatic.c sipomatic.h

sipomatic_LDADD= 	$(INTLLIBS)  \
					$(top_builddir)/coreapi/liblinphone.la

AM_CFLAGS=$(STRICT_OPTIONS)  -DENABLE_TRACE -D_ORTP_SOURCE $(VIDEO_CFLAGS) $(READLINE_CFLAGS)

#in order to workaround a arm-linux cross-compilation libtool bug
#we need to explicit again the dependencies of the executables:
if ARMBUILD
AM_LDFLAGS= 	$(top_builddir)/mediastreamer2/src/libquickstream.la \
		$(top_builddir)/mediastreamer2/src/libmediastreamer.la \
		$(top_builddir)/oRTP/src/libortp.la \
		$(SPEEX_LIBS) \
		$(OSIP_LIBS)
endif
