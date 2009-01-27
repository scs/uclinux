# $Id: Makefile.am,v 1.19 2008/05/06 09:35:51 asuraparaju Exp $
#

DISTCLEANFILES = dirac-stdint.h

INCLUDES = -I$(top_srcdir) -I$(srcdir) -I$(top_builddir)

h_sources = arith_codec.h arrays.h band_codec.h band_vlc.h\
            common_types.h common.h picture.h picture_buffer.h \
            mot_comp.h motion.h mv_codec.h pic_io.h upconvert.h \
            wavelet_utils.h cmd_line.h dirac_assertions.h dirac_types.h \
            mot_comp_mmx.h video_format_defaults.h dirac_exception.h \
			dirac-stdint.h

cpp_sources = arith_codec.cpp band_codec.cpp band_vlc.cpp common.cpp \
              picture.cpp picture_buffer.cpp mot_comp.cpp motion.cpp \
              mv_codec.cpp pic_io.cpp upconvert.cpp wavelet_utils.cpp \
              cmd_line.cpp dirac_assertions.cpp upconvert_mmx.cpp \
              wavelet_utils_mmx.cpp mot_comp_mmx.cpp \
              video_format_defaults.cpp dirac_exception.cpp

if USE_MSVC
noinst_LIBRARIES = libdirac_common.a
libdirac_common_a_AR = link.exe -lib /out:libdirac_common.a $(libdirac_common_a_OBJECTS) ; echo
libdirac_common_a_SOURCES = $(h_sources) $(cpp_sources)
else
libdirac_common_a_AR = ar crv
noinst_LTLIBRARIES = libdirac_common.la
libdirac_common_la_SOURCES = $(h_sources) $(cpp_sources)
libdirac_common_la_CXXFLAGS = $(AM_CXXFLAGS)
endif



library_includedir=$(includedir)/$(GENERIC_LIBRARY_NAME)/libdirac_common
library_include_HEADERS = common_types.h dirac_inttypes.h dirac-stdint.h dirac_types.h

if USE_MSVC
CLEANFILES = *.pdb *.ilk
endif

