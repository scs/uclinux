VER = linphone-3.0.0

CFLAGS += -fno-strict-aliasing -ffast-math -mfast-fp

CONF_OPTS = \
	--enable-portaudio=no \
	--enable-gtk_ui=no \
	--disable-manual \
	--disable-strict \
	--disable-glib \
	--enable-ipv6=no \
	--disable-shared \
	--enable-static \
	--with-osip=$(STAGEDIR)/usr \
	$(call USE_ENABLE,USER_BFIN_LINPHONE_VIDEO,video)

# Don't require the intltool utils since we aren't going to actually
# run them -- they're required in maintainer mode (linphone dev)
export ac_cv_path_INTLTOOL_UPDATE  = true
export ac_cv_path_INTLTOOL_MERGE   = true
export ac_cv_path_INTLTOOL_EXTRACT = true

include $(ROOTDIR)/tools/autotools.mk

romfs:
	$(ROMFSINST) -d build-$(VER)/console/linphonec /usr/bin/linphonec
	$(ROMFSINST) -d $(VER)/share/ringback.wav /usr/share/sounds/linphone/ringback.wav
	$(ROMFSINST) -d $(VER)/share/rings/oldphone.wav /usr/share/sounds/linphone/rings/oldphone.wav
