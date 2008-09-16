VER = expat-2.0.1

TARGETS-y = install
TARGETS-$(CONFIG_USER_EXPAT_EXAMPLES) += examples/elements examples/outline

all: build-$(VER)/Makefile
	$(MAKE) -C build-$(VER) DESTDIR=$(STAGEDIR) $(TARGETS-y)

build-$(VER)/Makefile:
	find $(VER) -type f -print0 | xargs -0 touch -r $(VER)/configure
	set -e ; \
	rm -rf build-$(VER) ; \
	mkdir build-$(VER) ; \
	cd build-$(VER) ; \
	../$(VER)/configure $(CONFIGURE_OPTS)

clean:
	rm -rf build*

romfs:
	$(ROMFSINST) -d -e CONFIG_FMT_USE_FDPIC_ELF $(STAGEDIR)/usr/lib/libexpat.so.1 /usr/lib/libexpat.so.1
	$(ROMFSINST) -d -e CONFIG_USER_EXPAT_EXAMPLES build-$(VER)/examples/elements /usr/bin/elements
	$(ROMFSINST) -d -e CONFIG_USER_EXPAT_EXAMPLES build-$(VER)/examples/outline /usr/bin/outline

.PHONY: all clean romfs
