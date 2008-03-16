VER = genext2fs-1.4.1-cvs

all: build-host-$(VER)/Makefile
	$(MAKE) -C build-host-$(VER)

build-host-$(VER)/Makefile:
	find $(VER) -type f -print0 | xargs -0 touch -r $(VER)/configure
	set -e ; \
	rm -rf build-host-$(VER) ; \
	mkdir build-host-$(VER) ; \
	cd build-host-$(VER) ; \
	CFLAGS="" CPPFLAGS="" LDFLAGS="" CC="" AR="" RANLIB="" \
	../$(VER)/configure

clean:
	rm -rf build*

romfs:

.PHONY: all clean romfs
