lib_LTLIBRARIES = libvrtx.la

libvrtx_la_LDFLAGS = -version-info 0:0:0 -lpthread

libvrtx_la_SOURCES = \
	event.c \
	heap.c \
	init.c \
	mb.c \
	mx.c \
	pt.c \
	queue.c \
	sem.c \
	task.c \
	time.c

libvrtx_la_CPPFLAGS = \
	@XENO_USER_CFLAGS@ \
	-I$(top_srcdir)/include
