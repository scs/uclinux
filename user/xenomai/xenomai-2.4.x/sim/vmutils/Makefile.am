lib_LTLIBRARIES = libmvmutils.la

libmvmutils_la_SOURCES = \
	clock.cc \
	elf.c \
	hash++.cc \
	interface.cc \
	list++.cc \
	object.cc \
	statobj.cc \
	string++.cc \
	tclist++.cc \
	utils.c

libmvmutils_la_LDFLAGS = -version-info 1:0:0

noinst_HEADERS = \
	clock.h \
	hash++.h \
	interface.h \
	list++.h \
	object.h \
	statobj.h \
	string++.h \
	tclist++.h \
	toolshop.h \
	version.h

libmvmutils_la_CXXFLAGS = \
	@MVM_CXXFLAGS@ \
	-D__XENO_SIM__ \
	-I$(srcdir)/..

libmvmutils_la_CFLAGS = \
	@MVM_CFLAGS@ \
	-D__XENO_SIM__ \
	-I$(srcdir)/..

noinst_PROGRAMS = tclpack

tclpack_SOURCES = tclpack.l

DISTCLEANFILES = tclpack.c

dist-hook:
	rm -f $(distdir)/tclpack.c
