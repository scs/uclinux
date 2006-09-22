all: build/Makefile
	$(MAKE) -C build -f Makefile install DESTDIR=$$PWD/DESTDIR

build/Makefile:
	touch *
	set -e ; \
	rm -rf build ; \
	mkdir build ; \
	cd build ; \
	../configure --host=bfin-uclinux --prefix=/usr

distclean:
	rm -rf build DESTDIR

clean %::
	if [ -f build/Makefile ] ; then $(MAKE) -C build -f Makefile $@ || exit $$? ; fi

clean::
	rm -rf DESTDIR
