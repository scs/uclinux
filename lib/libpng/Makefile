VER = libpng-1.2.16

all: build/Makefile
	$(MAKE) -C build install DESTDIR=$(STAGEDIR)

build/Makefile:
	find $(VER) -type f -print0 | xargs -0 touch -r $(VER)/configure
	set -e ; \
	rm -rf build ; \
	mkdir build ; \
	cd build ; \
	../$(VER)/configure $(CONFIGURE_OPTS)

clean:
	rm -rf build

romfs:
	for l in libpng12.so.0 libpng.so.3 ; do \
		$(ROMFSINST) -d -e CONFIG_FMT_USE_FDPIC_ELF $(STAGEDIR)/usr/lib/$$l /usr/lib/$$l || exit $$? ; \
	done

.PHONY: all clean romfs
