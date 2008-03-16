VER = genext2fs-1.4.1-cvs

all: build-host/Makefile
	$(MAKE) -C build-host

build-host/Makefile:
	find $(VER) -type f -print0 | xargs -0 touch -r $(VER)/configure
	set -e ; \
	rm -rf build-host ; \
	mkdir build-host ; \
	cd build-host ; \
	CFLAGS="" CPPFLAGS="" LDFLAGS="" CC="" AR="" RANLIB="" \
	../$(VER)/configure

clean:
	rm -rf build*

romfs:

.PHONY: all clean romfs
