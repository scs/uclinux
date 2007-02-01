all: build/Makefile
	$(MAKE) -C build
	install -m 0644 -D build/libfl.a $(STAGEDIR)/usr/lib/libfl.a

build/Makefile: Makefile
	find . -type f -print0 | xargs -0 touch -r configure
	set -e ; \
	rm -rf build ; \
	mkdir build ; \
	cd build ; \
	../configure $(CONFIGURE_OPTS)

romfs:

clean:
	rm -rf build

.PHONY: all clean romfs
