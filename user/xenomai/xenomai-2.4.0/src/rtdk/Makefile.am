lib_LTLIBRARIES = librtdk.la

librtdk_la_LDFLAGS = -version-info 0:0:0 -lpthread

librtdk_la_SOURCES = \
	init.c \
	rt_print.c

librtdk_la_CPPFLAGS = \
	@XENO_USER_CFLAGS@ \
	-I$(top_srcdir)/include

noinst_HEADERS = internal.h
