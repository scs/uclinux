# $Id: Makefile.am,v 1.13 2008/08/14 02:18:22 asuraparaju Exp $
#

INCLUDES = -I$(top_srcdir) -I$(srcdir) -I$(top_builddir)

h_sources = comp_decompress.h picture_decompress.h seq_decompress.h \
            decoder_types.h dirac_cppparser.h dirac_parser.h

cpp_sources = comp_decompress.cpp picture_decompress.cpp seq_decompress.cpp \
             dirac_cppparser.cpp dirac_parser.cpp

if USE_MSVC
lib_LIBRARIES = libdirac_decoder.a
libdirac_decoder_a_AR = link -lib -out:libdirac_decoder.a $(libdirac_decoder_a_OBJECTS); link $(LIBFLAGS) -out:libdirac_decoder$(LIBEXT) $(LDFLAGS) $(libdirac_decoder_a_OBJECTS) $(libdirac_decoder_a_DEPENDENCIES); echo
else
lib_LTLIBRARIES = libdirac_decoder.la
endif
libdirac_decoder_a_SOURCES = $(h_sources) $(cpp_sources)

libdirac_decoder_a_LIBADD = \
               $(top_builddir)/libdirac_common/libdirac_common.a \
               $(top_builddir)/libdirac_byteio/libdirac_byteio.a 

libdirac_decoder_la_SOURCES = $(h_sources) $(cpp_sources)
libdirac_decoder_la_CXXFLAGS = $(AM_CXXFLAGS)

libdirac_decoder_la_LIBADD = $(top_builddir)/libdirac_common/libdirac_common.la $(top_builddir)/libdirac_byteio/libdirac_byteio.la

libdirac_decoder_la_LDFLAGS= -no-undefined -version-info $(GENERIC_LIBRARY_VERSION) -export-symbols-regex '^dirac_'

library_includedir=$(includedir)/$(GENERIC_LIBRARY_NAME)/libdirac_decoder
library_include_HEADERS = dirac_parser.h decoder_types.h

if USE_MSVC
install-exec-local: libdirac_decoder.lib
	    $(mkinstalldirs) "$(DESTDIR)$(libdir)"; \
	    echo " $(INSTALL_PROGRAM) libdirac_decoder.lib $(DESTDIR)$(libdir)/libdirac_decoder.lib"; \
	    $(INSTALL_PROGRAM) libdirac_decoder.lib $(DESTDIR)$(libdir)/libdirac_decoder.lib || exit 1; \
	for ext in dll pdb; do \
	  file="libdirac_decoder.$$ext"; \
	  if test -f "$$file"; then \
	    $(mkinstalldirs) "$(DESTDIR)$(bindir)"; \
	    echo " $(INSTALL_PROGRAM) $$file $(DESTDIR)$(bindir)/$$file"; \
	    $(INSTALL_PROGRAM) "$$file" "$(DESTDIR)$(bindir)/$$file" || exit 1; \
	  fi \
	done

uninstall-local:
	for file in \
	  "$(DESTDIR)$(bindir)/libdirac_decoder.dll" \
	  "$(DESTDIR)$(bindir)/libdirac_decoder.pdb" \
	  "$(DESTDIR)$(libdir)/libdirac_decoder.lib"; \
	  do \
	  if test -f "$$file"; then \
	    echo " rm -f" "$$file"; \
	    rm -f "$$file"; \
	  fi \
	done
endif
if USE_MSVC
CLEANFILES = *.pdb *.ilk *.dll *.lib *.exp *.a
endif
