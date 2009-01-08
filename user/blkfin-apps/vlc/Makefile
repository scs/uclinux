VER = vlc-0.8.6b
USE_ENABLE = $(shell test "$(CONFIG_$(1))" = "y" && echo "--enable-$(2)" || echo "--disable-$(2)")

all: build/Makefile
	$(MAKE) -C build install DESTDIR=$$PWD/DESTDIR

build/Makefile:
	find $(VER) -type f -print0 | xargs -0 touch -r $(VER)/configure
	set -e ; \
	rm -rf build ; \
	mkdir build ; \
	cd build ; \
	../$(VER)/configure \
		$(CONFIGURE_OPTS) \
		--with-included-gettext \
		--enable-v4l \
		--enable-static \
		--enable-mostly-builtin \
		$(call USE_ENABLE,LIB_ALSA_LIB,alsa) \
		$(call USE_ENABLE,SOUND_OSS_CORE,oss) \
		$(call USE_ENABLE,LIB_LIBMAD,mad) \
		--disable-wxwidgets \
		--disable-skins2 \
		--disable-mozilla \
		--without-mozilla \
		--disable-x11 \
		--without-x \
		--disable-macosx \
		--without-macosx-sdk \
		--disable-macosx-audio \
		--disable-cdda \
		--disable-cddax \
		--disable-cdio \
		--disable-libcddb \
		--disable-freetype \
		--disable-hal \
		--disable-growl \
		--disable-dvdnav \
		--disable-dshow \
		--disable-smb \
		--disable-gnomevfs \
		--disable-vcd \
		--disable-mkv \
		--disable-mod \
		$(call USE_ENABLE,LIB_LIBSDL,sdl) \
		--disable-a52 \
		--disable-dts \
		--disable-vorbis \
		$(call USE_ENABLE,LIB_SPEEX,speex) \
		--disable-libxml2 \
		$(call USE_ENABLE,FB,fb)

clean:
	rm -rf build DESTDIR

romfs:
	$(ROMFSINST) -d DESTDIR/usr/bin/vlc /usr/bin/vlc
	set -e ; \
	cd DESTDIR ; \
	for l in `find -name '*.so'` ; do \
		$(ROMFSINST) -d $$l /$$l ; \
	done
	# ipv6 is disabled by default ...
	rm -f $(ROMFSDIR)/usr/lib/vlc/misc/libipv6_plugin.so

.PHONY: all clean romfs
