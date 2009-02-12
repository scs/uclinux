vpath %.c $(top_srcdir)/../ksrc/skins/posix

includesubdir = $(prefix)/include/asm-sim

CC = $(top_builddir)/gcic/gcic

override CFLAGS = -g

if CONFIG_XENO_MVM_ATOMIC_CORE
atomic_core := --no-inst -O2
endif

AM_CPPFLAGS = \
	-D_GNU_SOURCE -D__IN_XENO__ \
	--gcic-backend=$(prefix)/libexec/gcic \
	--skin-code \
	$(atomic_core) \
	-I$(top_srcdir)/../ksrc/skins \
	-I$(top_srcdir)/../include \
	-I$(srcdir)/..

lib_LIBRARIES = libposix_sim.a

nodist_libposix_sim_a_SOURCES = \
	sched.c \
	thread_attr.c \
	thread.c \
	mutex_attr.c \
	mutex.c \
	cond_attr.c \
	cond.c \
	sem.c \
	cancel.c \
	once.c \
	signal.c \
	tsd.c \
	clock.c \
	timer.c \
	intr.c \
	registry.c \
	mq.c \
	shm.c \
	module.c

includesub_HEADERS = \
	posix_overrides.h

SUBDIRS = . testsuite demos

