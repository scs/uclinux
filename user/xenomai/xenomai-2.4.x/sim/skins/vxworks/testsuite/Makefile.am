CC = ../../../gcic/gcic

override CFLAGS=-g

INCLUDES = \
	-D__IN_XENO__ \
	--gcic-backend=$(prefix)/libexec/gcic \
	-I$(srcdir)/.. \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/../include \
	-I$(top_srcdir)/../include/vxworks

LDFLAGS = \
	-u __xeno_user_init \
	--gcic-backend=$(prefix)/libexec/gcic \
	--cc=$(CXX) \
	--no-mvm-libs \
	libtests.a \
	../libvxworks_sim.a \
	../../../nucleus/libnucleus_sim.a \
	../../../adapter/libadapter.a \
	../../../vm/libmvm.la \
	../../../vmutils/libmvmutils.la

check_PROGRAMS= \
	trestart \
	t010726-1 \
	t010726-2 \
	t010728 \
	t010820-1 \
	t010820-2 \
	t010823-1 \
	t010823-2

trestart_DEPENDENCIES= ../libvxworks_sim.a libtests.a
t010726_1_DEPENDENCIES= ../libvxworks_sim.a libtests.a
t010726_2_DEPENDENCIES= ../libvxworks_sim.a libtests.a
t010728_DEPENDENCIES= ../libvxworks_sim.a libtests.a
t010820_1_DEPENDENCIES= ../libvxworks_sim.a libtests.a
t010820_2_DEPENDENCIES= ../libvxworks_sim.a libtests.a
t010823_1_DEPENDENCIES= ../libvxworks_sim.a libtests.a
t010823_2_DEPENDENCIES= ../libvxworks_sim.a libtests.a

check_LIBRARIES=libtests.a

libtests_a_SOURCES = xntest.c
libtests_a_DEPENDENCIES = xntest.h vxworks_test.h
trestart_SOURCES = trestart.c
t010726_1_SOURCES = t010726-1.c
t010726_2_SOURCES = t010726-2.c
t010728_SOURCES = t010728.c
t010820_1_SOURCES = t010820-1.c
t010820_2_SOURCES = t010820-2.c
t010823_1_SOURCES = t010823-1.c
t010823_2_SOURCES = t010823-2.c

EXTRA_DIST = $(libtests_a_DEPENDENCIES)
