vpath %.c $(top_srcdir)/../ksrc/skins/vxworks

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
	-I$(top_srcdir)/../ksrc/skins \
	-I$(top_srcdir)/../include

lib_LIBRARIES = libvxworks_sim.a

nodist_libvxworks_sim_a_SOURCES = \
	errnoLib.c \
	intLib.c \
	kernelLib.c \
	module.c \
	msgQLib.c \
	semLib.c \
	sysLib.c \
	taskHookLib.c \
	taskInfo.c \
	taskLib.c \
	tickLib.c \
	wdLib.c

SUBDIRS=testsuite
