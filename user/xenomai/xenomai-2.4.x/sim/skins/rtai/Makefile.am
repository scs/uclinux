vpath %.c $(top_srcdir)/../ksrc/skins/rtai

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
	-I$(top_srcdir)/../include

lib_LIBRARIES = librtai_sim.a

nodist_librtai_sim_a_SOURCES = \
	intr.c \
	module.c \
	sem.c \
	task.c \
	timer.c
