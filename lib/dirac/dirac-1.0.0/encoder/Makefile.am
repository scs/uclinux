# $Id: Makefile.am,v 1.12 2008/05/06 09:35:51 asuraparaju Exp $
#

INCLUDES = -I$(top_srcdir) -I$(top_builddir)

bin_PROGRAMS = dirac_encoder

dirac_encoder_SOURCES = encmain.cpp

if USE_MSVC
LDADD = ../libdirac_encoder/libdirac_encoder.a ../libdirac_common/libdirac_common.a ../libdirac_motionest/libdirac_motionest.a ../libdirac_byteio/libdirac_byteio.a
else
LDADD = ../libdirac_encoder/libdirac_encoder.la $(CONFIG_MATH_LIB)
if USE_STATIC
dirac_encoder_LDFLAGS = $(LDFLAGS) -static
else
endif
endif
if USE_MSVC
CLEANFILES = *.pdb *.ilk
endif
