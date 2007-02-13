SUBDIRS=win_receiver win_sender

noinst_PROGRAMS= rtpsend rtprecv mrtpsend mrtprecv test_timer rtpmemtest tevrtpsend tevrtprecv tevmrtprecv

rtpsend_SOURCES= rtpsend.c

rtprecv_SOURCES= rtprecv.c

mrtpsend_SOURCES= mrtpsend.c

mrtprecv_SOURCES= mrtprecv.c

rtpmemtest_SOURCES= rtpmemtest.c

test_timer_SOURCES= test_timer.c

tevrtpsend_SOURCES= tevrtpsend.c

tevrtprecv_SOURCES= tevrtprecv.c

tevmrtprecv_SOURCES= tevmrtprecv.c

AM_CFLAGS=  -D_ORTP_SOURCE $(PTHREAD_CFLAGS) $(GLIB_CFLAGS)
AM_LDFLAGS= $(PTHREAD_LDFLAGS)
LDADD=$(top_builddir)/src/libortp.la
INCLUDES=-I$(top_srcdir)/include/
