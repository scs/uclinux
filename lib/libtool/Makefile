all: build/Makefile
	$(MAKE) -C build install DESTDIR=$$PWD/DESTDIR

build/Makefile:
	touch * */*
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
