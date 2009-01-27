# $Id: Makefile.am,v 1.6 2004/12/10 15:21:41 asuraparaju Exp $
#

INCLUDES = -I$(top_srcdir) -I$(srcdir) -Ilibinstr

bin_PROGRAMS = dirac_instrumentation

h_sources = process_sequence.h

cpp_sources = process_sequence.cpp instrmain.cpp

dirac_instrumentation_SOURCES = $(h_sources) $(cpp_sources)

if USE_MSVC
LDADD = ../../libdirac_encoder/libdirac_encoder.a ../../libdirac_common/libdirac_common.a ../../libdirac_motionest/libdirac_motionest.a libdirac_instrument/libdirac_instrument.a
else
LDADD = ../../libdirac_encoder/libdirac_encoder.la libdirac_instrument/libdirac_instrument.la $(CONFIG_MATH_LIB)
if USE_STATIC
dirac_instrumentation_LDFLAGS = $(LDFLAGS) -static
endif
endif

if USE_MSVC
CLEANFILES = *.pdb *.ilk
endif

SUBDIRS=libdirac_instrument
