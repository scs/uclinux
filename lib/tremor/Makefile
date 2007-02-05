all: build/Makefile
	$(MAKE) -C build install DESTDIR=$(STAGEDIR)
	install -d $(STAGEDIR)/usr/include/tremor
	install -m0644 config_types.h ivorbisfile.h ivorbiscodec.h ogg.h os_types.h $(STAGEDIR)/usr/include/tremor

build/Makefile:
	find . -type f -print0 | xargs -0 touch -r configure
	set -e ; \
	rm -rf build ; \
	mkdir build ; \
	cd build ; \
	../configure $(CONFIGURE_OPTS)

clean:
	rm -rf build

romfs:

.PHONY: all clean romfs
