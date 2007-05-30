VER = avahi-0.6.19

CONF_OPTS = \
	--with-distro=none \
	--disable-dbus \
	--disable-gtk \
	--disable-glib \
	--disable-qt3 \
	--disable-qt4 \
	--disable-expat \
	--disable-gdbm \
	--disable-libdaemon \
	--disable-doxygen-man --disable-doxygen-rtf --disable-doxygen-xml --disable-doxygen-chm --disable-doxygen-chi --disable-manpages

all: build-$(VER)/Makefile
	$(MAKE) -C build-$(VER) install DESTDIR=$(STAGEDIR)

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
	$(ROMFSINST) -d -e CONFIG_FMT_USE_FDPIC_ELF $(STAGEDIR)/usr/lib/$$l /usr/lib/$$l

.PHONY: all clean romfs
