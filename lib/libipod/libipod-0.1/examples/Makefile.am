noinst_PROGRAMS = dumptracks dumptracks_cpp readwritedb teststrings

INCLUDES = -I$(top_srcdir)/src -I$(top_srcdir)/include

dumptracks_SOURCES = dumptracks.c
dumptracks_LDADD = $(top_builddir)/src/libipod.la

dumptracks_cpp_SOURCES = dumptracks_cpp.cpp
dumptracks_cpp_LDADD = $(top_builddir)/src/libipod.la

readwritedb_SOURCES = readwritedb.c
readwritedb_LDADD = $(top_builddir)/src/libipod.la

teststrings_SOURCES = teststrings.c
teststrings_LDADD = $(top_builddir)/src/libipod.la
