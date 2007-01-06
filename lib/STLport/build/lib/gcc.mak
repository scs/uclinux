# -*- Makefile -*- Time-stamp: <03/10/12 20:35:49 ptr>
# $Id: gcc.mak,v 1.1.2.3 2005/09/26 19:34:19 dums Exp $

SRCROOT := ..
COMPILER_NAME := gcc

STLPORT_INCLUDE_DIR = ../../stlport
include Makefile.inc
include ${SRCROOT}/Makefiles/top.mak


INCLUDES += -I$(STLPORT_INCLUDE_DIR)

ifeq ($(OSNAME),linux)
DEFS += -D_STLP_REAL_LOCALE_IMPLEMENTED -D_GNU_SOURCE
endif

# options for build with boost support
ifdef STLP_BUILD_BOOST_PATH
INCLUDES += -I$(STLP_BUILD_BOOST_PATH)
endif

