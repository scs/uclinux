# $Id: Makefile.am,v 1.5 2004/11/26 13:36:25 asuraparaju Exp $
#

INCLUDES = -I$(top_srcdir) -I$(srcdir)

bin_PROGRAMS=dirac_unittest

dirac_unittest_SOURCES = utmain.cpp \
                         core_suite.h \
                         cppunit_testsuite.cpp \
						 arrays_test.h \
						 arrays_test.cpp \
						 frames_test.h \
						 frames_test.cpp \
						 motion_comp_test.h \
						 motion_comp_test.cpp \
                         wavelet_utils_test.h \
                         wavelet_utils_test.cpp
if USE_MSVC
LDADD = ../libdirac_encoder/libdirac_encoder.a ../libdirac_common/libdirac_common.a ../libdirac_motionest/libdirac_motionest.a -ldl -lcppunit
else
LDADD = ../libdirac_encoder/libdirac_encoder.la ../libdirac_decoder/libdirac_decoder.la -ldl -lcppunit
if USE_STATIC
dirac_unittest_LDFLAGS = $(LDFLAGS) -static
endif
endif

if USE_MSVC
CLEANFILES = *.pdb *.ilk
endif
