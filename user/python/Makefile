VER = python-2.4.4

all: build-$(VER)/Makefile
	$(MAKE) -C build-$(VER) altinstall DESTDIR=$(STAGEDIR)

build-$(VER)/Makefile: build-$(VER)-cross/python
	find $(VER) -type f -print0 | xargs -0 touch -r $(VER)/configure
	set -e ; \
	rm -rf build-$(VER) ; \
	mkdir build-$(VER) ; \
	cd build-$(VER) ; \
	OPT="$(CFLAGS)" \
	../$(VER)/configure \
		--with-cxx=no \
		$(CONFIGURE_OPTS)

build-$(VER)-cross/python: build-$(VER)-cross/Makefile
	$(MAKE) -C build-$(VER)-cross python Parser/pgen

build-$(VER)-cross/Makefile:
	find $(VER) -type f -print0 | xargs -0 touch -r $(VER)/configure
	set -e ; \
	rm -rf build-$(VER)-cross ; \
	mkdir build-$(VER)-cross ; \
	cd build-$(VER)-cross ; \
	OPT="-O1 -pipe" CFLAGS="" CPPFLAGS="" LDFLAGS="" CC="" AR="" RANLIB="" \
	../$(VER)/configure \
		--with-cxx=no

romfs:
	$(ROMFSINST) -d $(STAGEDIR)/usr/bin/python* /usr/bin/python

clean:
	rm -rf build*

.PHONY: all clean romfs
