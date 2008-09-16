lib_LTLIBRARIES = librtai.la

librtai_la_LDFLAGS = -version-info 0:0:0

librtai_la_SOURCES = init.c \
	shm.c

librtai_la_CPPFLAGS = \
	@XENO_USER_CFLAGS@ \
	-I$(top_srcdir)/include
