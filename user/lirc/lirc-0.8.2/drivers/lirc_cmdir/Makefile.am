## $Id: Makefile.am,v 1.2 2005/08/01 05:55:25 lirc Exp $

## Process this file with automake to produce Makefile.in

## this is so that Automake includes the C compiling definitions, and
## includes the source files in the distribution.
EXTRA_PROGRAMS = automake_dummy
automake_dummy_SOURCES = lirc_cmdir.c lirc_cmdir.h

## there is no *just* object file support in automake.  This is close enough
module_DATA = lirc_cmdir.o

include ../Makefile.common
