all: Makefile
	$(MAKE) -f Makefile

Makefile:
	./configure --host=bfin-uclinux --prefix=/usr

clean distclean::
	$(MAKE) -f Makefile distclean

%::
	if [ -f Makefile ] ; then $(MAKE) -f Makefile $@ || exit $$? ; fi
