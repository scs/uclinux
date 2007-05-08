all: build/Makefile
	$(MAKE) -C build install DESTDIR=$(STAGEDIR)

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
	$(ROMFSINST) -d -e CONFIG_FMT_USE_FDPIC_ELF $(STAGEDIR)/usr/lib/libid3tag.so.0 /usr/lib/libid3tag.so.0

.PHONY: all clean romfs
