VER = ircp-0.3

all: build-$(VER)/Makefile
	$(MAKE) -C build-$(VER)

build-$(VER)/Makefile:
	find $(VER) -type f -print0 | xargs -0 touch -r $(VER)/configure
	set -e ; \
	rm -rf build-$(VER) ; \
	mkdir build-$(VER) ; \
	cd build-$(VER) ; \
	OPENOBEX_CONFIG=$(STAGEDIR)/usr/bin/openobex-config \
	../$(VER)/configure \
		$(CONFIGURE_OPTS)

clean:
	rm -rf build*

romfs:
	$(ROMFSINST) -d build-$(VER)/src/ircp /bin/ircp

.PHONY: all clean romfs
