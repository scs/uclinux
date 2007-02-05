all: build/Makefile
	$(MAKE) -C build install DESTDIR=$$PWD/DESTDIR
	# keep libtool / pkg-config from breaking crap
	rm -f DESTDIR/usr/lib/*.la
	sed -i "/^prefix=/s:=.*:=$$PWD/DESTDIR/usr:" DESTDIR/usr/lib/pkgconfig/speex.pc

build/Makefile:
	find . -type f -print0 | xargs -0 touch -r configure
	set -e ; \
	rm -rf build ; \
	mkdir build ; \
	cd build ; \
	../configure \
		--host=$(CONFIGURE_HOST) \
		--prefix=/usr \
		--without-ogg \
		--enable-blackfin-asm \
		--enable-fixed-point

clean:
	rm -rf build DESTDIR

%::
	if [ -f build/Makefile ] ; then $(MAKE) -C build -f Makefile $@ || exit $$? ; fi

romfs:
	@true
