VER = python-2.4.4

CONF_OPTS = \
	$(CONFIGURE_SHARED_ENABLE) \
	--with-cxx=no

export PYTHON_DONTCOMPILE = 1
export PYTHON_DISABLE_SSL = 1
export PYTHON_DISABLE_MODULES = bz2 nis readline pyexpat dbm gdbm bsddb _curses _curses_panel _tkinter

all: build-$(VER)/Makefile
	$(MAKE) \
		-C build-$(VER) \
		altinstall \
		DESTDIR=$(STAGEDIR) \
		HOSTPYTHON=$$PWD/build-$(VER)-cross/python \
		HOSTPGEN=$$PWD/build-$(VER)-cross/Parser/pgen

build-$(VER)/Makefile: build-$(VER)-cross/python
	find $(VER) -type f -print0 | xargs -0 touch -r $(VER)/configure
	set -e ; \
	rm -rf build-$(VER) ; \
	mkdir build-$(VER) ; \
	cd build-$(VER) ; \
	OPT="$(CFLAGS)" \
	../$(VER)/configure $(CONF_OPTS) $(CONFIGURE_OPTS)

build-$(VER)-cross/python: build-$(VER)-cross/Makefile
	$(MAKE) -C build-$(VER)-cross python Parser/pgen

build-$(VER)-cross/Makefile:
	find $(VER) -type f -print0 | xargs -0 touch -r $(VER)/configure
	set -e ; \
	rm -rf build-$(VER)-cross ; \
	mkdir build-$(VER)-cross ; \
	cd build-$(VER)-cross ; \
	OPT="-O1 -pipe" CFLAGS="" CPPFLAGS="" LDFLAGS="" CC="" AR="" RANLIB="" \
	../$(VER)/configure --with-cxx=no --disable-shared

romfs:
	$(ROMFSINST) -d $(STAGEDIR)/usr/bin/python* /usr/bin/python
	$(ROMFSINST) -d -e CONFIG_FMT_USE_FDPIC_ELF $(STAGEDIR)/usr/lib/libpython2.4.so.1.0 /usr/lib/libpython2.4.so.1.0

clean:
	rm -rf build*

.PHONY: all clean romfs
