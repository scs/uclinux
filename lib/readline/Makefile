ifeq ($(CONFIG_FMT_USE_FDPIC_ELF),y)
READLINE_SHARED = install-shared
else
READLINE_SHARED =
endif

all: build/Makefile
	$(MAKE) -C build install $(READLINE_SHARED) DESTDIR=$(STAGEDIR)
	rm -f $(STAGEDIR)/usr/lib/*.old

build/Makefile:
	find . -type f -print0 | xargs -0 touch -r configure
	set -e ; \
	rm -rf build ; \
	mkdir build ; \
	cd build ; \
	CROSS_COMPILE="" ../configure $(CONFIGURE_OPTS)

clean:
	rm -rf build

romfs:
	$(ROMFSINST) -e CONFIG_FMT_USE_FDPIC_ELF $(STAGEDIR)/usr/lib/libreadline.so.5 /lib/

.PHONY: all clean romfs
