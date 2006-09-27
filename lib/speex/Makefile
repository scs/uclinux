all: build/Makefile
	$(MAKE) -C build -f Makefile install DESTDIR=$$PWD/DESTDIR

build/Makefile:
	touch *
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

distclean:
	rm -rf build DESTDIR

clean %::
	if [ -f build/Makefile ] ; then $(MAKE) -C build -f Makefile $@ || exit $$? ; fi

clean::
	rm -rf DESTDIR

romfs:
	@true
