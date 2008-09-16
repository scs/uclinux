#
#  $Id: Makefile.am,v 1.16 2006/01/26 02:51:10 bmidgley Exp $
#

noinst_LIBRARIES = libsbc.a

libsbc_a_SOURCES = sbc.h sbc.c sbc_tables.h sbc_math.h
libsbc_a_DEPENDENCIES = $(libsbc_a_SOURCES)

if AO
ao_programs = sbcdec_ao
ao_cflags   = @AO_CFLAGS@
else
ao_programs =
ao_cflags   =
endif

if FIXED
fixed_cflags = -DUSE_FIXED
else
fixed_cflags =
endif

noinst_PROGRAMS = sbcinfo sbcdec sbcenc rcplay $(ao_programs)

sbcdec_LDADD = libsbc.a
sbcenc_LDADD = libsbc.a

rcplay_LDADD = @BLUEZ_LIBS@ -lbluetooth

if AO
sbcdec_ao_LDADD = @AO_LIBS@ libsbc.a
endif

AM_CFLAGS = $(ao_cflags) $(fixed_cflags) @BLUEZ_CFLAGS@

MAINTAINERCLEANFILES = Makefile.in
