all: build/Makefile
	$(MAKE) -C build install DESTDIR=$(STAGEDIR)

build/Makefile:
	find . -type f -print0 | xargs -0 touch -r configure
	set -e ; \
	rm -rf build ; \
	mkdir build ; \
	cd build ; \
	../configure \
		$(CONFIGURE_OPTS) \
		--disable-aso \
		--enable-fpm=no

clean:
	rm -rf build

romfs:
ifeq ($(CONFIG_FMT_USE_FDPIC_ELF),y)
	$(ROMFSINST) $(STAGEDIR)/usr/lib/libmad.so.0 /lib/
endif

.PHONY: all clean romfs
