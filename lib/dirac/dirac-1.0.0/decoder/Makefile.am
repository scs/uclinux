# $Id: Makefile.am,v 1.11 2007/03/29 14:08:10 asuraparaju Exp $
#

INCLUDES = -I$(top_srcdir) -I$(srcdir)

bin_PROGRAMS = dirac_decoder

dirac_decoder_SOURCES = decmain.cpp

if USE_MSVC
LDADD = ../libdirac_decoder/libdirac_decoder.a  ../libdirac_common/libdirac_common.a ../libdirac_byteio/libdirac_byteio.a
else
LDADD = ../libdirac_decoder/libdirac_decoder.la $(CONFIG_MATH_LIB)
if USE_STATIC
dirac_decoder_LDFLAGS = $(LDFLAGS) -static
endif
endif

if USE_MSVC
CLEANFILES = *.pdb *.ilk
endif
