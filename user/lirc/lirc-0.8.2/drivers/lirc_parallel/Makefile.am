## $Id: Makefile.am,v 5.14 2004/04/25 16:29:27 lirc Exp $

## Process this file with automake to produce Makefile.in

## this is so that Automake includes the C compiling definitions, and
## includes the source files in the distribution.
EXTRA_PROGRAMS = automake_dummy
automake_dummy_SOURCES = lirc_parallel.c lirc_parallel.h

## there is no *just* object file support in automake.  This is close enough
module_DATA = lirc_parallel.o

include ../Makefile.common
