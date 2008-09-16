VER = mpeg2dec-0.4.1

all: build/Makefile
	$(MAKE) -C build install DESTDIR=$(STAGEDIR)

build/Makefile:
	find $(VER) -type f -print0 | xargs -0 touch -r $(VER)/configure
	set -e ; \
	rm -rf build ; \
	mkdir build ; \
	cd build ; \
	../$(VER)/configure \
		$(CONFIGURE_OPTS) \
		--enable-shared \
		--enable-static \
		--disable-sdl

clean:
	rm -rf build

romfs:
	$(ROMFSINST) -d -e CONFIG_FMT_USE_FDPIC_ELF $(STAGEDIR)/usr/lib/libmpeg2.so.0 /usr/lib/libmpeg2.so.0
	$(ROMFSINST) -d -e CONFIG_FMT_USE_FDPIC_ELF $(STAGEDIR)/usr/lib/libmpeg2convert.so.0 /usr/lib/libmpeg2convert.so.0

.PHONY: all clean romfs
