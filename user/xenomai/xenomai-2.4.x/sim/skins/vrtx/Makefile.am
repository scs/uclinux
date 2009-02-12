vpath %.c $(top_srcdir)/../ksrc/skins/vrtx

CC = $(top_builddir)/gcic/gcic

override CFLAGS = -g

if CONFIG_XENO_MVM_ATOMIC_CORE
atomic_core := --no-inst -O2
endif

AM_CPPFLAGS = \
	-D__IN_XENO__ \
	--gcic-backend=$(prefix)/libexec/gcic \
	--skin-code \
	$(atomic_core) \
	-I$(srcdir)/../include \
	-I$(top_srcdir)/../include \
	-I$(top_srcdir)/../ksrc/skins

lib_LIBRARIES = libvrtx_sim.a

nodist_libvrtx_sim_a_SOURCES = \
	event.c \
	heap.c \
	mb.c \
	module.c \
	mx.c \
	pt.c \
	queue.c \
	sem.c \
	task.c \
	time.c
