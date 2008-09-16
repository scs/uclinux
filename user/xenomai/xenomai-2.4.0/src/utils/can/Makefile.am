sbin_PROGRAMS = rtcanconfig

bin_PROGRAMS = rtcanrecv rtcansend


CPPFLAGS = \
	@XENO_USER_CFLAGS@ \
	-I$(top_srcdir)/include

LDFLAGS = \
	@XENO_USER_LDFLAGS@ \
	-L../../skins/native \
	-L../../skins/rtdm


rtcanconfig_SOURCES = rtcanconfig.c

rtcanconfig_LDADD = -lrtdm


rtcanrecv_SOURCES = rtcanrecv.c

rtcanrecv_LDADD = -lnative -lrtdm


rtcansend_SOURCES = rtcansend.c

rtcansend_LDADD = -lnative -lrtdm
