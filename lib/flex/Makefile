all: build/Makefile
	$(MAKE) -C build
	install -m 0644 -D build/libfl.a $(STAGEDIR)/usr/lib/libfl.a

build/Makefile: Makefile
	find . -type f -print0 | xargs -0 touch -r configure
	set -e ; \
	rm -rf build ; \
	mkdir build ; \
	cd build ; \
	../configure \
		--host=$(CONFIGURE_HOST) \
		--build=$(CONFIGURE_BUILD) \
		--prefix=/usr
# this is an old configure script which means $(CONFIGURE_OPTS) wont work

romfs:

clean:
	rm -rf build

.PHONY: all clean romfs
