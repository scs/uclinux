# $Id: Makefile.am,v 1.13 2008/08/27 00:17:11 asuraparaju Exp $
#

INCLUDES = -I$(top_srcdir) -I$(srcdir)

h_sources = block_match.h downconvert.h me_mode_decn.h me_subpel.h me_utils.h pixel_match.h me_utils_mmx.h

cpp_sources = block_match.cpp downconvert.cpp me_mode_decn.cpp me_subpel.cpp me_utils.cpp pixel_match.cpp me_utils_mmx.cpp downconvert_mmx.cpp

if USE_MSVC
noinst_LIBRARIES = libdirac_motionest.a
libdirac_motionest_a_AR = link.exe -lib /out:libdirac_motionest.a $(libdirac_motionest_a_OBJECTS) ; echo
else
libdirac_motionest_a_AR = ar crv
noinst_LTLIBRARIES = libdirac_motionest.la
endif

libdirac_motionest_a_SOURCES = $(h_sources) $(cpp_sources)

libdirac_motionest_la_SOURCES = $(h_sources) $(cpp_sources)
libdirac_motionest_la_CXXFLAGS = $(AM_CXXFLAGS)


if USE_MSVC
CLEANFILES = *.pdb *.ilk 
endif

