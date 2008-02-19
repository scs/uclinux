VER = linphone-2.1.1

CFLAGS += -fno-strict-aliasing -ffast-math -mfast-fp

CONF_OPTS = \
	--enable-portaudio=no \
	--enable-gnome_ui=no \
	--disable-manual \
	--disable-strict \
	--disable-glib \
	--enable-ipv6=no \
	--disable-shared \
	--enable-static \
	--with-osip=$(STAGEDIR)/usr \
	$(call USE_ENABLE,USER_BFIN_LINPHONE_VIDEO,video)

include $(ROOTDIR)/tools/autotools.mk

romfs:
	$(ROMFSINST) -d build-$(VER)/console/linphonec /usr/bin/linphonec
	$(ROMFSINST) -d $(VER)/share/ringback.wav /usr/share/sounds/linphone/ringback.wav
	$(ROMFSINST) -d $(VER)/share/rings/oldphone.wav /usr/share/sounds/linphone/rings/oldphone.wav
