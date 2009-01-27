# $Id: Makefile.am,v 1.5 2004/11/22 13:54:47 asuraparaju Exp $
#

INCLUDES = -I$(top_srcdir) -I$(srcdir)

h_sources = setstdiomode.h bitmap.h

cpp_sources = setstdiomode.cpp bitmap.cpp

noinst_LIBRARIES = libconv_common.a

libconv_common_a_SOURCES = $(h_sources) $(cpp_sources)

if USE_MSVC
CLEANFILES = *.pdb *.ilk
endif

if USE_MSVC
libconv_common_a_AR = link.exe -lib /out:libconv_common.a $(libconv_common_a_OBJECTS) ; echo
else
libconv_common_a_AR = ar crv
endif
