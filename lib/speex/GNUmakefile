all: Makefile
	$(MAKE) -f Makefile

Makefile:
	./configure \
		--host=$(CONFIGURE_HOST) \
		--prefix=/usr \
		--without-ogg \
		--enable-blackfin-asm \
		--enable-fixed-point

%::
	if [ -f Makefile ] ; then $(MAKE) -f Makefile $@ || exit $$? ; fi

romfs:
	@true
