all: build/Makefile
	$(MAKE) \
		-C build install \
		includedir=$(STAGEDIR)/usr/include \
		libdir=$(STAGEDIR)/usr/lib \
		bindir=$(STAGEDIR)/usr/bin

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
	$(ROMFSINST) $(STAGEDIR)/usr/bin/dmalloc /bin

.PHONY: all clean romfs
