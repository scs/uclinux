# To create your own version, just unpack ffmpeg tarball here
# and update the VER variable.  Or export your own from their
# svn via:
# svn export -r <REV> svn://svn.mplayerhq.hu/ffmpeg/trunk ffmpeg-svn-<REV>
VER = ffmpeg-svn-11114

all: build/Makefile
	$(MAKE) -C build
	$(MAKE) -C build DESTDIR=$(STAGEDIR) install

build/Makefile:
	find $(VER) -type f -print0 | xargs -0 touch -r $(VER)/configure
	set -e ; \
	rm -rf build ; \
	mkdir build ; \
	cd build ; \
	SDL_CONFIG=$(STAGEDIR)/usr/bin/sdl-config \
	../$(VER)/configure \
		--prefix=/usr \
		--source-path=$$PWD/../$(VER) \
		--target-os=Linux \
		--cpu=bfin \
		--arch=bfin \
		--extra-ldflags="$(LDFLAGS)" \
		--enable-static \
		--enable-shared \
		--enable-gpl \
		--enable-pp \
		--disable-strip \
		--cross-prefix=$(CONFIGURE_HOST)-
	sed -i '/^LDCONFIG/s:=.*:=true:' build/config.mak

#		--enable-swscaler

clean:
	rm -rf build

romfs:
	set -e ; \
	cd $(STAGEDIR)/usr/lib ; \
	for l in libavcodec.so.?? libavdevice.so.?? libavformat.so.?? libavutil.so.?? libpostproc.so.?? vhook/* ; do \
		$(ROMFSINST) -d -e CONFIG_FMT_USE_FDPIC_ELF $$l /usr/lib/$$l ; \
	done
	$(ROMFSINST) -d -e CONFIG_USER_FFMPEG_APPS $(STAGEDIR)/usr/bin/ffmpeg /usr/bin/ffmpeg
	$(ROMFSINST) -d -e CONFIG_USER_FFMPEG_APPS $(STAGEDIR)/usr/bin/ffserver /usr/bin/ffserver
	$(ROMFSINST) -d -e CONFIG_USER_FFMPEG_APPS -e CONFIG_LIB_LIBSDL $(STAGEDIR)/usr/bin/ffplay /usr/bin/ffplay

.PHONY: all clean romfs
