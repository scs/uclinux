VER = vlc-0.8.6b

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
		--enable-alsa \
		--enable-oss \
		--disable-mad \
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
		--disable-sdl \
		--disable-a52 \
		--disable-dts \
		--disable-vorbis \
		--disable-speex \
		--disable-libxml2

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
