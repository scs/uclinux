all: Makefile
	$(MAKE) -f Makefile
	$(MAKE) -f Makefile install DESTDIR=$$PWD/DESTDIR
	rm -f DESTDIR/usr/lib/*.old

Makefile:
	CROSS_COMPILE="" ./configure --host=$(CONFIGURE_HOST) --prefix=/usr

clean distclean %::
	if [ -f Makefile ] ; then $(MAKE) -f Makefile $@ || exit $$? ; fi

clean distclean::
	rm -rf DESTDIR

romfs:
ifeq ($(CONFIG_BLACKFIN_USE_FDPIC),y)
	mv DESTDIR/usr/lib/libreadline.so* $(ROMFSDIR)/lib/
endif

.PHONY: all clean distclean romfs
