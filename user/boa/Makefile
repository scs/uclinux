VER = boa-0.94.14rc21

FLTFLAGS = -s 65536

all: build-$(VER)/Makefile
	$(MAKE) -C build-$(VER)

build-$(VER)/Makefile:
	find $(VER) -type f -print0 | xargs -0 touch -r $(VER)/configure
	set -e ; \
	rm -rf build-$(VER) ; \
	mkdir build-$(VER) ; \
	cd build-$(VER) ; \
	../$(VER)/configure $(CONFIGURE_OPTS) $(CONF_OPTS)

clean:
	rm -rf build*

romfs:
	$(ROMFSINST) build-$(VER)/src/boa /bin/boa

.PHONY: all clean romfs
