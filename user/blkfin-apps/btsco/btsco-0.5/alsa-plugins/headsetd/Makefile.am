
if ALSAPLUGIN

bin_PROGRAMS = headsetd

headsetd_SOURCES        = headsetd.c daemon.c states.c sdp.c volctl.c dbus.c \
			  daemon.h states.h sdp.h sockets.h volctl.h dbus.h

headsetd_LDADD          = @BLUEZ_LIBS@

endif
