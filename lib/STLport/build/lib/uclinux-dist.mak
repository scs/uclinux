#
# stolen and fixed from gcc.mk,  check for updates there
# davidm@snapgear.com
#

SRCROOT := $(ROOTDIR)/lib/STLport/build
COMPILER_NAME := gcc
OSNAME := linux
BUILD_OSNAME := $(shell uname -s | tr '[A-Z]' '[a-z]' | tr ', /\\()"' ',//////' | tr ',/' ',-')

ifdef CONFIG_LIB_STLPORT_SHARED
ALL_TAGS      := all-shared
INSTALL_TAGS  := install-release-shared
else
ALL_TAGS      := all-static
INSTALL_TAGS  := install-release-static
endif

STLPORT_INCLUDE_DIR = $(ROOTDIR)/include/STLport
include Makefile.inc
#
# override LIBNAME
#
LIBNAME := stdc++

include ${SRCROOT}/Makefiles/top.mak


INCLUDES += -I$(STLPORT_INCLUDE_DIR) -I$(ROOTDIR)/include

ifeq ($(OSNAME),linux)
DEFS += -D_STLP_REAL_LOCALE_IMPLEMENTED -D_GNU_SOURCE
endif

# options for build with boost support
ifdef STLP_BUILD_BOOST_PATH
INCLUDES += -I$(STLP_BUILD_BOOST_PATH)
endif

LDSEARCH      += -L$(ROOTDIR)/uClibc/lib
