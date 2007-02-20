all: build/Makefile
	$(MAKE) -C build install DESTDIR=$$PWD/DESTDIR

build/Makefile:
	find . -type f -print0 | xargs -0 touch -r configure
	set -e ; \
	rm -rf build ; \
	mkdir build ; \
	cd build ; \
	../configure \
		$(CONFIGURE_OPTS) \
		--with-bluez=$(STAGINGDIR) \
		--without-openobex \
		--without-dbus \
		--without-fuse \
		--with-alsa=$(STAGINGDIR) \
		--with-usb=$(STAGINGDIR)

clean:
	rm -rf build DESTDIR

romfs:
	rm -rf DESTDIR/usr/share/man DESTDIR/usr/share/info
	cp -pPR DESTDIR/* $(ROMFSDIR)

.PHONY: all clean romfs
