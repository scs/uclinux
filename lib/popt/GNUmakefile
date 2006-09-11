all: Makefile
	$(MAKE) -f Makefile

Makefile:
	./configure --host=bfin-uclinux --prefix=/usr

romfs:
	@true

%::
	if [ -f Makefile ] ; then $(MAKE) -f Makefile $@ || exit $$? ; fi
