all: build/Makefile
	$(MAKE) -C build -f Makefile install DESTDIR=$$PWD/DESTDIR
	rm -f DESTDIR/usr/lib/*.old

build/Makefile:
	touch *
	set -e ; \
	rm -rf build ; \
	mkdir build ; \
	cd build ; \
	CROSS_COMPILE="" ../configure --host=$(CONFIGURE_HOST) --prefix=/usr

distclean:
	rm -rf build DESTDIR

clean %::
	if [ -f build/Makefile ] ; then $(MAKE) -C build -f Makefile $@ || exit $$? ; fi

clean::
	rm -rf DESTDIR

romfs:
ifeq ($(CONFIG_BLACKFIN_USE_FDPIC),y)
	mv DESTDIR/usr/lib/libreadline.so* $(ROMFSDIR)/lib/
endif

.PHONY: all clean distclean romfs
