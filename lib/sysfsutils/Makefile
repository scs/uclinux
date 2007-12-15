VER = sysfsutils-2.1.0

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
	#$(ROMFSINST) build/systool /bin/systool
	$(ROMFSINST) -e CONFIG_FMT_USE_FDPIC_ELF $(STAGEDIR)/lib/libsysfs.so.2 /lib/libsysfs.so.2

.PHONY: all clean romfs
