# $Id: Makefile.am,v 1.20 2008/09/16 04:23:55 asuraparaju Exp $
#

SUBDIRS = libdirac_byteio libdirac_common libdirac_motionest libdirac_encoder \
          libdirac_decoder encoder decoder util $(CPPUNITTESTS_DIR) \
          tests $(DOC_DIR) win32

.PHONY: valgrind-check
valgrind-check:
	cd tests && $(MAKE) $(AM_MAKEFLAGS) $@

if HAVE_DOXYGEN
DOC_DIR = doc
else
DOC_DIR =
endif

if HAVE_LATEX
DOC_DIR = doc
endif

if HAVE_CPPUNIT
CPPUNITTESTS_DIR = unit_tests
endif

EXTRA_DIST = bootstrap

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = dirac.pc


.PHONY: codec
codec:
	for dir in "libdirac_common" "libdirac_byteio" "libdirac_motionest" "libdirac_encoder" "libdirac_decoder"; do (cd $$dir && $(MAKE) $(AM_MAKEFLAGS)) ; done
	cd encoder && $(MAKE) $(AM_MAKEFLAGS)
	cd decoder && $(MAKE) $(AM_MAKEFLAGS)

.PHONY: codec-check
codec-check:
	for dir in "libdirac_common" "libdirac_byteio" "libdirac_motionest" "libdirac_encoder" "libdirac_decoder"; do (cd $$dir && $(MAKE) $(AM_MAKEFLAGS)) ; done
	cd encoder && $(MAKE) $(AM_MAKEFLAGS)
	cd decoder && $(MAKE) $(AM_MAKEFLAGS)
	cd util/instrumentation && $(MAKE) $(AM_MAKEFLAGS)
if HAVE_CPPUNIT
	cd unit_tests && $(MAKE) $(AM_MAKEFLAGS)
endif
	cd tests && $(MAKE) $(AM_MAKEFLAGS)
	cd tests && $(MAKE) $(AM_MAKEFLAGS) check

.PHONY: encoder
encoder:
	for dir in "libdirac_common" "libdirac_byteio" "libdirac_motionest" "libdirac_encoder" ; do (cd $$dir && $(MAKE) $(AM_MAKEFLAGS)) ; done
	cd encoder && $(MAKE) $(AM_MAKEFLAGS)

.PHONY: decoder
decoder:
	for dir in "libdirac_common" "libdirac_byteio" "libdirac_decoder" ; do (cd $$dir && $(MAKE) $(AM_MAKEFLAGS)) ; done
	cd decoder && $(MAKE) $(AM_MAKEFLAGS)

.PHONY: instrumentation
instrumentation:
	for dir in "libdirac_common" "libdirac_byteio" "libdirac_motionest" "libdirac_encoder" ; do (cd $$dir && $(MAKE) $(AM_MAKEFLAGS)) ; done
	cd util/instrumentation && $(MAKE) $(AM_MAKEFLAGS)

.PHONY: conversion
conversion:
	cd util/conversion && $(MAKE) $(AM_MAKEFLAGS)

.PHONY: unit_tests
unit_tests:
	for dir in "libdirac_common" "libdirac_byteio" "libdirac_motionest" "libdirac_encoder" "libdirac_decoder"; do (cd $$dir && $(MAKE) $(AM_MAKEFLAGS)) ; done
	cd unit_tests && $(MAKE) $(AM_MAKEFLAGS)

.PHONY: doc
doc:
	cd doc && $(MAKE) $(AM_MAKEFLAGS)
