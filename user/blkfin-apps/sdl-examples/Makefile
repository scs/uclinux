DIRS = $(dir $(wildcard */configure))

DIRS_makefiles = $(patsubst %,build-%/Makefile,$(DIRS))

all: $(DIRS_makefiles)
	for d in $(DIRS) ; do $(MAKE) -C build-$$d || exit $$? ; done

%/Makefile:
	set -e ; \
	VER=$(patsubst build-%/Makefile,%,$@) ; \
	find $${VER} -type f -print0 | xargs -0 touch -r $${VER}/configure ; \
	rm -rf build-$${VER} ; \
	mkdir build-$${VER} ; \
	cd build-$${VER} ; \
	SDL_CONFIG=$(STAGEDIR)/usr/bin/sdl-config \
	../$${VER}/configure $(CONFIGURE_OPTS) --without-x

clean:
	rm -rf build-*

romfs:
	$(ROMFSINST) -d build-aliens-1.0.2/aliens /usr/bin/aliens
	$(ROMFSINST) -d aliens-1.0.2/data /usr/bin/data
	$(ROMFSINST) -d build-fire-1.0/fire /usr/bin/fire
	$(ROMFSINST) -d build-plasma-1.0/plasma /usr/bin/plasma
	$(ROMFSINST) -d build-sdldoom-1.10/doom /usr/bin/doom
	$(ROMFSINST) -d doom1.wad /usr/bin/doom1.wad
	$(ROMFSINST) -d build-newvox-1.0/newvox /usr/bin/newvox
	$(ROMFSINST) -d build-sdlroids-1.3.4/sdlroids /usr/bin/sdlroids
	$(ROMFSINST) -d sdlroids-1.3.4/sounds /usr/bin/sounds
	$(ROMFSINST) -d sdlroids-1.3.4/bmp /usr/bin/bmp
	$(ROMFSINST) -d build-sierp-1.0/sierp /usr/bin/sierp
	$(ROMFSINST) -d build-warp-1.1/warp /usr/bin/warp
	$(ROMFSINST) -d warp-1.1/leeloo.bmp /usr/bin/bmp/leeloo.bmp
	$(ROMFSINST) -d build-water-1.0/water /usr/bin/water
	$(ROMFSINST) -d water-1.0/water320.bmp /usr/bin/water320.bmp
	$(ROMFSINST) -d build-xflame-1.0/xflame /usr/bin/xflame
	$(ROMFSINST) -d build-ballfield-1.0/ballfield /usr/bin/ballfield
	$(ROMFSINST) -d ballfield-1.0/font7x10.bmp /usr/bin/bmp/font7x10.bmp
	$(ROMFSINST) -d ballfield-1.0/logo.bmp /usr/bin/bmp/logo.bmp
	$(ROMFSINST) -d ballfield-1.0/blueball.png /usr/bin/bmp/blueball.png
	$(ROMFSINST) -d ballfield-1.0/redball.png /usr/bin/bmp/redball.png
	$(ROMFSINST) -d ballfield-1.0/redbluestars.png /usr/bin/bmp/redbluestars.png
	$(ROMFSINST) -d build-dd2-0.2.2/src/dd2 /usr/bin/dd2
	$(ROMFSINST) -d dd2-0.2.2/src/data /usr/share/dd2
	rm -f $(ROMFSDIR)/usr/share/dd2/Makefile.*
	$(ROMFSINST) -d build-vp-1.7/src/vp /usr/bin/vp

.PHONY: all clean romfs
