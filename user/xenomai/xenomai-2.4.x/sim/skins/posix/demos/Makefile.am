vpath %.c $(top_srcdir)/../examples/posix

CC = $(top_builddir)/gcic/gcic

if CONFIG_XENO_MVM_ATOMIC_CORE
atomic_core := --no-inst -O2
endif

AM_CFLAGS=-Wall -g -Werror-implicit-function-declaration

INCLUDES = \
	-D_GNU_SOURCE -D__IN_XENO__ -DPRODUCER -DCONSUMER \
	--gcic-backend=$(prefix)/libexec/gcic \
	-I$(srcdir)/.. \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/../include

AM_LDFLAGS = \
	-u __xeno_user_init \
	--gcic-backend=$(prefix)/libexec/gcic \
	--cc=$(CXX) \
	--no-mvm-libs \
	../libposix_sim.a \
	../../../nucleus/libnucleus_sim.a \
	../../../adapter/libadapter.a \
	../../../vm/libmvm.la \
	../../../vmutils/libmvmutils.la

check_PROGRAMS=satch_sim

nodist_satch_sim_SOURCES=satch.c
