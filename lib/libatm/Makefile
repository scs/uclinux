VER = linux-atm-2.4.0

all: build-$(VER)/Makefile
	$(MAKE) -C build-$(VER) install DESTDIR=$(STAGEDIR)

build-$(VER)/Makefile:
	find $(VER) -type f -print0 | xargs -0 touch -r $(VER)/configure
	set -e ; \
	rm -rf build-$(VER) ; \
	mkdir build-$(VER) ; \
	cd build-$(VER) ; \
	CROSS_COMPILE="" \
	../$(VER)/configure $(CONFIGURE_OPTS)

clean:
	rm -rf build-*

romfs:
	$(ROMFSINST) -d -e CONFIG_FMT_USE_FDPIC_ELF $(STAGEDIR)/usr/lib/libatm.so.1 /usr/lib/

.PHONY: all clean romfs
