VER = libusb-0.1.12

all: build-$(VER)/Makefile
	$(MAKE) -C build-$(VER) install DESTDIR=$(STAGEDIR)

build-$(VER)/Makefile:
	find $(VER) -type f -print0 | xargs -0 touch -r $(VER)/configure
	set -e ; \
	rm -rf build-$(VER) ; \
	mkdir build-$(VER) ; \
	cd build-$(VER) ; \
	../$(VER)/configure $(CONFIGURE_OPTS)

clean:
	rm -rf build-$(VER)

romfs:
	$(ROMFSINST) -d -e CONFIG_FMT_USE_FDPIC_ELF $(STAGEDIR)/usr/lib/libusb-0.1.so.4 /usr/lib/libusb-0.1.so.4
	$(ROMFSINST) -d -e CONFIG_FMT_USE_FDPIC_ELF $(STAGEDIR)/usr/lib/libusbpp-0.1.so.4 /usr/lib/libusbpp-0.1.so.4

.PHONY: all clean romfs
