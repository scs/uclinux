lib_LTLIBRARIES = libpsos.la

libpsos_la_LDFLAGS = -version-info 0:0:0 -lpthread

libpsos_la_SOURCES = \
	asr.c \
	init.c \
	queue.c \
	rn.c \
	sem.c \
	task.c \
	tm.c

libpsos_la_CPPFLAGS = \
	@XENO_USER_CFLAGS@ \
	-I$(top_srcdir)/include
