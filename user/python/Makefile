all: build/Makefile
	$(MAKE) -C build altinstall DESTDIR=$(STAGEDIR)

build/Makefile: build-cross/python
	set -e ; \
	rm -rf build ; \
	mkdir build ; \
	cd build ; \
	OPT="$(CFLAGS)" \
	../configure \
		--with-cxx=no \
		$(CONFIGURE_OPTS)

build-cross/python: build-cross/Makefile
	$(MAKE) -C build-cross python Parser/pgen

build-cross/Makefile:
	set -e ; \
	rm -rf build-cross ; \
	mkdir build-cross ; \
	cd build-cross ; \
	OPT="-O1" CFLAGS="" LDFLAGS="" CC="" AR="" RANLIB="" \
	../configure \
		--with-cxx=no

romfs:
	$(ROMFSINST) -d $(STAGEDIR)/usr/bin/python* /usr/bin/python

clean:
	rm -rf build build-cross

.PHONY: all clean romfs
