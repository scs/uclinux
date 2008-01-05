VER = readline-5.2_p1

TARGETS-y =
TARGETS-$(CONFIG_FMT_USE_FDPIC_ELF) += install-shared

all: build-$(VER)/Makefile
	$(MAKE) -C build-$(VER) install $(TARGETS-y) DESTDIR=$(STAGEDIR)
	rm -f $(STAGEDIR)/usr/lib/*.old

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
	$(ROMFSINST) -e CONFIG_FMT_USE_FDPIC_ELF $(STAGEDIR)/usr/lib/libreadline.so.5 /lib/
	$(ROMFSINST) -e CONFIG_FMT_USE_FDPIC_ELF $(STAGEDIR)/usr/lib/libhistory.so.5 /lib/

.PHONY: all clean romfs
