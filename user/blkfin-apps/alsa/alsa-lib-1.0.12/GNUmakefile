all: Makefile
	$(MAKE) -f Makefile
	$(MAKE) -f Makefile install DESTDIR=$$PWD/DESTDIR

Makefile:
	./configure --host=bfin-uclinux --prefix=/usr

%::
	if [ -f Makefile ] ; then $(MAKE) -f Makefile $@ || exit $$? ; fi
