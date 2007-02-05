all: build/Makefile
	$(MAKE) -C build install DESTDIR=$$PWD/DESTDIR
	# keep libtool from breaking us
	rm -f DESTDIR/usr/lib/*.la

build/Makefile:
	find . -type f -print0 | xargs -0 touch -r configure
	set -e ; \
	rm -rf build ; \
	mkdir build ; \
	cd build ; \
	../configure --host=$(CONFIGURE_HOST) --prefix=/usr

clean:
	rm -rf build DESTDIR

%::
	if [ -f build/Makefile ] ; then $(MAKE) -C build -f Makefile $@ || exit $$? ; fi

romfs:
