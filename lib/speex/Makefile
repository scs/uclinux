ifndef CONFIG_FMT_USE_FDPIC_ELF
CFLAGS="-Wl,-elf2flt=-s100000"
endif

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
		--without-ogg \
		--enable-blackfin-asm \
		--enable-fixed-point

clean:
	rm -rf build

romfs:
	$(ROMFSINST) -e CONFIG_FMT_USE_FDPIC_ELF $(STAGEDIR)/usr/lib/libspeex.so.1 /lib/

.PHONY: all clean romfs
