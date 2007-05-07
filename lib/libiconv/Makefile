VER = libiconv-1.11

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
	$(ROMFSINST) -e CONFIG_FMT_USE_FDPIC_ELF $(STAGEDIR)/usr/lib/libiconv.so.2 /lib/

.PHONY: all clean romfs
