all: build/Makefile
	$(MAKE) -C build -f Makefile install DESTDIR=$$PWD/DESTDIR

build/Makefile:
	find . -type f -print0 | xargs -0 touch -r configure
	set -e ; \
	rm -rf build ; \
	mkdir build ; \
	cd build ; \
	../configure --host=bfin-uclinux --prefix=/usr/local --with-softfloat

clean:
	rm -rf build DESTDIR

%::
	if [ -f build/Makefile ] ; then $(MAKE) -C build -f Makefile $@ || exit $$? ; fi

romfs:
	if [ "$(CONFIG_LIB_ALSA_LIB)" = "y" ] || [ "$(CONFIG_LIB_ALSA_LIB_FORCE)" = "y" ] ; then \
		for conf in `cd DESTDIR ; find usr/local/share/alsa -type f` ; do \
			$(ROMFSINST) -d DESTDIR/$$conf /$$conf || exit $$? ; \
		done ; \
	fi
ifeq ($(CONFIG_FMT_USE_FDPIC_ELF),y)
	cp -P $$PWD/DESTDIR/usr/local/lib/libasound.so* $(ROMFSDIR)/lib/
endif

