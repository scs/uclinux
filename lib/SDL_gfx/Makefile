VER = SDL_gfx-2.0.16

all: build-$(VER)/Makefile
	$(MAKE) -C build-$(VER) install DESTDIR=$(STAGEDIR)

build-$(VER)/Makefile:
	find $(VER) -type f -print0 | xargs -0 touch -r $(VER)/configure
	set -e ; \
	rm -rf build-$(VER) ; \
	mkdir build-$(VER) ; \
	cd build-$(VER) ; \
	SDL_CONFIG=$(STAGEDIR)/usr/bin/sdl-config \
	../$(VER)/configure $(CONFIGURE_OPTS)

clean:
	rm -rf build*

romfs:
	$(ROMFSINST) -d -e CONFIG_FMT_USE_FDPIC_ELF $(STAGEDIR)/usr/lib/libSDL_net-1.2.so.0 /usr/lib/libSDL_net-1.2.so.0

.PHONY: all clean romfs
