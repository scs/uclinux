VER = linphone-2.0.1

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
	--with-osip=$(STAGEDIR)/usr

ifeq ($(CONFIG_USER_BFIN_LINPHONE_VIDEO),)
CONF_OPTS += --disable-video
endif

all: build-$(VER)/Makefile
	$(MAKE) -C build-$(VER)

build-$(VER)/Makefile:
	find $(VER) -type f -print0 | xargs -0 touch -r $(VER)/configure
	set -e ; \
	rm -rf build-$(VER) ; \
	mkdir build-$(VER) ; \
	cd build-$(VER) ; \
	DOXYGEN=false \
	../$(VER)/configure $(CONFIGURE_OPTS) $(CONF_OPTS)

romfs:
	$(ROMFSINST) -d build-$(VER)/console/linphonec /usr/bin/linphonec
	$(ROMFSINST) -d $(VER)/share/ringback.wav /usr/share/sounds/linphone/ringback.wav
	$(ROMFSINST) -d $(VER)/share/rings/oldphone.wav /usr/share/sounds/linphone/rings/oldphone.wav

clean:
	rm -rf build-*

.PHONY: all clean romfs
