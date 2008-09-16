#!/usr/bin/make -f

ARM7_CFLAGS := -mtune=arm7tdmi -mcpu=arm7tdmi \
   -fomit-frame-pointer -DNDEBUG \
   -O3 -pipe

builddir = $(shell echo $@ | sed 's,^[a-zA-Z0-9]\+-,build/,')
testdir = test -d $(builddir) || mkdir -p $(builddir)
msg = @echo "Run  \`make -C $(builddir)'  to build MPD"

opts_common := --disable-http \
   --with-audio=oss \
   --disable-alsa \
   --disable-shout \
   --disable-id3 \
   --disable-mod \
   --disable-audiofile \
   --enable-static --disable-shared \
   --enable-flac --enable-mpd-flac --disable-sse --disable-3dnow
common_conf = $(testdir); cd $(builddir) && ../../configure $(opts_common)
uclinux_opts := --host=arm-elf --enable-uclinux \
                LDFLAGS="-Wl,-elf2flt -Wl,-O1" \
                CFLAGS="$(ARM7_CFLAGS)"

yes_vorbis := --enable-ogg --enable-mpd-ivorbis
no_vorbis := --disable-ogg

yes_mp3 := --enable-mp3 --enable-mpd-mad
no_mp3 := --disable-mp3

configure:
	./autogen.sh

configure-mpd-local: configure
	$(common_conf) \
		$(yes_vorbis) $(yes_mp3) CFLAGS="-fno-inline -g -pipe"
	$(msg)

configure-mpd: configure
	$(common_conf) $(uclinux_opts) \
	        $(no_vorbis) \
	        $(no_mp3)
	$(msg)

configure-mpd-test: configure
	$(common_conf) $(uclinux_opts) \
	        $(yes_vorbis) \
	        $(yes_mp3) \
		--enable-aso --enable-fpm=arm --enable-speed
	$(msg)

build-%:
	test -d $(builddir) || $(MAKE) -f build.mk $(shell echo $@ | sed 's,^build-,configure-,')
	rm -f $(builddir)/src/mpd
	$(MAKE) -C $(builddir) -j8

rebuild-test:
	-$(MAKE) -C build/mpd-test distclean
	$(MAKE) -f build.mk configure-mpd-test
	$(MAKE) -C build/mpd-test -j8
