if ALSAPLUGIN

SUBDIRS = headsetd

alsadir = $(libdir)/alsa-lib

alsa_LTLIBRARIES = libasound_module_pcm_a2dp.la libasound_module_pcm_a2dpd.la libasound_module_ctl_a2dpd.la libasound_module_pcm_sco.la libasound_module_ctl_sco.la
#asound_module_pcm_sco_LTLIBRARIES = libasound_module_pcm_sco.la
#asound_module_ctl_sco_LTLIBRARIES = libasound_module_ctl_sco.la

asound_module_pcm_scodir = $(libdir)/alsa-lib
asound_module_ctl_scodir = $(libdir)/alsa-lib

libasound_module_pcm_a2dp_la_SOURCES = pcm_a2dp.c
libasound_module_pcm_a2dp_la_LIBADD = @ALSA_LIBS@ @BLUEZ_LIBS@ -lsbc -lpthread

libasound_module_pcm_a2dpd_la_SOURCES = pcm_a2dpd.c a2dp_timer.c a2dp_ipc.c
libasound_module_pcm_a2dpd_la_LIBADD = @ALSA_LIBS@ -lrt

libasound_module_ctl_a2dpd_la_SOURCES = ctl_a2dpd.c a2dp_ipc.c
libasound_module_ctl_a2dpd_la_LIBADD = @ALSA_LIBS@

libasound_module_pcm_sco_la_SOURCES = pcm_sco.c
libasound_module_pcm_sco_la_LIBADD = @ALSA_LIBS@ @BLUEZ_LIBS@ -lrt

libasound_module_ctl_sco_la_SOURCES = ctl_sco.c
libasound_module_ctl_sco_la_LIBADD = @ALSA_LIBS@

bin_PROGRAMS = a2dpd
a2dpd_SOURCES = a2dpd.c a2dplib.c alsalib.c resample.c
a2dpd_CFLAGS = $(AM_CFLAGS)
#a2dp_timer.c a2dp_ipc.c
a2dpd_LDADD = a2dp_timer.o a2dp_ipc.o @ALSA_LIBS@ @BLUEZ_LIBS@ -lsbc -lpthread -lrt

AM_CFLAGS = @ALSA_CFLAGS@ @BLUEZ_CFLAGS@ -pthread
#AM_LDFLAGS = -module -avoid-version -export-dynamic

#EXTRA_DIST = asound.conf

endif

MAINTAINERCLEANFILES = Makefile.in
