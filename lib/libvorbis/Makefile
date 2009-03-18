VER = libvorbis-1.2.0

all: build-$(VER)/Makefile
	$(MAKE) -C build-$(VER)
	$(MAKE) -C build-$(VER) install DESTDIR=$(STAGEDIR)

build-$(VER)/Makefile:
	find $(VER) -type f -print0 | xargs -0 touch -r $(VER)/configure
	set -e ; \
	rm -rf build-$(VER) ; \
	mkdir build-$(VER) ; \
	cd build-$(VER) ; \
	../$(VER)/configure $(CONFIGURE_OPTS)

clean:
	rm -rf build*

romfs:
	$(ROMFSINST) -d -e CONFIG_FMT_USE_FDPIC_ELF $(STAGEDIR)/usr/lib/libvorbisenc.so.2.0.3 /usr/lib/libvorbisenc.so.2.0.3
	$(ROMFSINST) -d -e CONFIG_FMT_USE_FDPIC_ELF $(STAGEDIR)/usr/lib/libvorbisfile.so.3.2.0 /usr/lib/libvorbisfile.so.3.2.0
	$(ROMFSINST) -d -e CONFIG_FMT_USE_FDPIC_ELF $(STAGEDIR)/usr/lib/libvorbis.so.0.4.0 /usr/lib/libvorbis.so.0.4.0

.PHONY: all clean romfs
