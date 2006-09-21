all: Makefile
	$(MAKE) -f Makefile
	$(MAKE) -f Makefile install DESTDIR=$$PWD/DESTDIR

Makefile:
	./configure \
		--host=$(CONFIGURE_HOST) \
		--prefix=/usr \
		--without-ogg \
		--enable-blackfin-asm \
		--enable-fixed-point

%::
	if [ -f Makefile ] ; then $(MAKE) -f Makefile $@ || exit $$? ; fi


clean distclean::
	$(MAKE) -f Makefile distclean
	rm -rf DESTDIR

romfs:
	@true
