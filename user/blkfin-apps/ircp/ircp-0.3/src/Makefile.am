#
#  $Id: Makefile.am,v 1.5 2002/11/30 18:55:55 holtmann Exp $
#

noinst_LIBRARIES = libircp.a

libircp_a_SOURCES = \
		ircp_client.c ircp_client.h \
		ircp_server.c ircp_server.h \
		ircp_io.c ircp_io.h \
		dirtraverse.c dirtraverse.h \
		debug.h ircp.h


bin_PROGRAMS = ircp 

ircp_SOURCES = ircp.c


LDADD = @OPENOBEX_LIBS@ libircp.a

INCLUDES = @OPENOBEX_CFLAGS@
