# $Id: Makefile.am,v 1.5 2008/05/06 09:35:51 asuraparaju Exp $
#

INCLUDES = -I$(top_srcdir) -I$(srcdir) -I$(top_builddir)

h_sources = accessunit_byteio.h displayparams_byteio.h parseunit_byteio.h \
            byteio.h picture_byteio.h codingparams_byteio.h dirac_byte_stream.h \
            parseparams_byteio.h mvdata_byteio.h mvdataelement_byteio.h \
            transform_byteio.h endofsequence_byteio.h component_byteio.h \
            subband_byteio.h dirac_byte_stats.h

cpp_sources = accessunit_byteio.cpp displayparams_byteio.cpp \
              parseunit_byteio.cpp byteio.cpp picture_byteio.cpp \
              codingparams_byteio.cpp dirac_byte_stream.cpp \
              parseparams_byteio.cpp mvdata_byteio.cpp  \
              mvdataelement_byteio.cpp \
              transform_byteio.cpp endofsequence_byteio.cpp \
              component_byteio.cpp subband_byteio.cpp dirac_byte_stats.cpp

if USE_MSVC
noinst_LIBRARIES = libdirac_byteio.a
libdirac_byteio_a_AR = link.exe -lib /out:libdirac_byteio.a $(libdirac_byteio_a_OBJECTS) ; echo
libdirac_byteio_a_SOURCES = $(h_sources) $(cpp_sources)
else
libdirac_byteio_a_AR = ar crv
noinst_LTLIBRARIES = libdirac_byteio.la
libdirac_byteio_la_SOURCES = $(h_sources) $(cpp_sources)
libdirac_byteio_la_CXXFLAGS = $(AM_CXXFLAGS)
endif



#library_includedir=$(includedir)/$(GENERIC_LIBRARY_NAME)/libdirac_common
#library_include_HEADERS = common_types.h dirac_types.h 

if USE_MSVC
CLEANFILES = *.pdb *.ilk
endif

