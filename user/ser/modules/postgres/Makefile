# $Id: Makefile,v 1.4 2003/07/30 16:29:00 lgfausak Exp $
#
# WARNING: do not run this directly, it should be run by the master Makefile

include ../../Makefile.defs
auto_gen=
NAME=postgres.so

# libpq-fe.h locations
DEFS +=-I/usr/local/pgsql/include -I/usr/include/postgresql
LIBS=-L$(LOCALBASE)/pgsql/lib -L$(LOCALBASE)/lib/pgsql -L/usr/pkg/lib \
		-L/usr/pkg/lib/pgsql -lpq

include ../../Makefile.modules
