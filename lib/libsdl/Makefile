VER = SDL-1.2.13

CONF_OPTS = \
	--disable-arts \
	--disable-esd \
	--disable-pth \
	--disable-video-directfb \
	--disable-video-x11

# upstream's install targets lack dependencies on the things
# they install, so just decouple build/install steps
all: build-$(VER)/Makefile
	$(MAKE) -C build-$(VER)
	$(MAKE) -C build-$(VER) install DESTDIR=$(STAGEDIR)

build-$(VER)/Makefile:
	find $(VER) -type f -print0 | xargs -0 touch -r $(VER)/configure
	set -e ; \
	rm -rf build-$(VER) ; \
	mkdir build-$(VER) ; \
	cd build-$(VER) ; \
	../$(VER)/configure $(CONFIGURE_OPTS) $(CONF_OPTS)

clean:
	rm -rf build*

romfs:
	$(ROMFSINST) -d -e CONFIG_FMT_USE_FDPIC_ELF $(STAGEDIR)/usr/lib/libSDL-1.2.so.0 /usr/lib/libSDL-1.2.so.0

.PHONY: all clean romfs
