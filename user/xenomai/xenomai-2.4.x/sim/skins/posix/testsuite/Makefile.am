CC = ../../../gcic/gcic

override CFLAGS=-g

INCLUDES = \
	-D__IN_XENO__ \
	--gcic-backend=$(prefix)/libexec/gcic \
	-I$(srcdir)/.. \
	-I$(top_srcdir)/include \
	-I$(top_srcdir)/../include

LDFLAGS = \
	-u __xeno_user_init \
	--gcic-backend=$(prefix)/libexec/gcic \
	--cc=$(CXX) \
	--no-mvm-libs \
	libtests.a \
	../libposix_sim.a \
	../../../nucleus/libnucleus_sim.a \
	../../../adapter/libadapter.a \
	../../../vm/libmvm.la \
	../../../vmutils/libmvmutils.la

check_PROGRAMS= \
	tthread \
	tsem \
	tmutex \
	tcond \
	tcancel \
	tsignal \
	ttsd \
	tclock \
	tmq \
	ttimers

tthread_DEPENDENCIES= ../libposix_sim.a libtests.a
tsem_DEPENDENCIES= ../libposix_sim.a libtests.a
tmutex_DEPENDENCIES=../libposix_sim.a libtests.a
tcond_DEPENDENCIES=../libposix_sim.a libtests.a
tcancel_DEPENDENCIES=../libposix_sim.a libtests.a
tsignal_DEPENDENCIES=../libposix_sim.a libtests.a
ttsd_DEPENDENCIES=../libposix_sim.a libtests.a
tclock_DEPENDENCIES=../libposix_sim.a libtests.a
ttimers_DEPENDENCIES=../libposix_sim.a libtests.a
tmq_DEPENDENCIES=../libposix_sim.a libtests.a

check_LIBRARIES=libtests.a

libtests_a_SOURCES = xntest.c
libtests_a_DEPENDENCIES = xntest.h posix_test.h
tthread_SOURCES = tthread.c
tsem_SOURCES = tsem.c
tmutex_SOURCES = tmutex.c
tcond_SOURCES = tcond.c
tcancel_SOURCES = tcancel.c
tsignal_SOURCES = tsignal.c
ttsd_SOURCES = ttsd.c
tclock_SOURCES = tclock.c
tmq_SOURCES = tmq.c
ttimers_SOURCES = ttimers.c

EXTRA_DIST = skeleton.c $(libtests_a_DEPENDENCIES)
