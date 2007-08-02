FLTFLAGS=-s 32000

all: Makefile
	$(MAKE) -f Makefile

Makefile:
	./configure \
		--host=$(CONFIGURE_HOST) \
		--prefix=/usr

%::
	if [ -f Makefile ] ; then $(MAKE) -f Makefile $@ || exit $$? ; fi

romfs:
	@true
