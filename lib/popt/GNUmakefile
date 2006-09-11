all: Makefile
	$(MAKE) -f Makefile

Makefile:
	./configure --host=$(CONFIGURE_HOST) --prefix=/usr

romfs:
	@true

%::
	if [ -f Makefile ] ; then $(MAKE) -f Makefile $@ || exit $$? ; fi
