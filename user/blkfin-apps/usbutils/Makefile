all: build/Makefile
	$(MAKE) -C build

build/Makefile:
	touch *
	set -e ; \
	rm -rf build ; \
	mkdir build ; \
	cd build ; \
	ac_cv_func_malloc_0_nonnull=yes \
	LDFLAGS="${LDFLAGS} -L$(ROOTDIR)/lib/libusb/DESTDIR/usr/lib" \
	CPPFLAGS="${CPPFLAGS} -I$(ROOTDIR)/lib/libusb/DESTDIR/usr/include" \
	../configure \
		--host=$(CONFIGURE_HOST) \
		--prefix=/usr

clean:
	rm -rf build DESTDIR

%::
	if [ -f Makefile ] ; then $(MAKE) -f Makefile $@ || exit $$? ; fi

romfs:
	$(ROMFSINST) build/lsusb /bin/
	$(ROMFSINST) usb.ids /usr/share
