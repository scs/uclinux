lib_LTLIBRARIES = libuitron.la

libuitron_la_LDFLAGS = -version-info 0:0:0 -lpthread

libuitron_la_SOURCES = \
	flag.c \
	init.c \
	mbx.c \
	sem.c \
	task.c

libuitron_la_CPPFLAGS = \
	@XENO_USER_CFLAGS@ \
	-I$(top_srcdir)/include
