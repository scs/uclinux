FLTFLAGS=-s 20000

all: build/Makefile
	$(MAKE) -C build

build/Makefile:
	touch *
	set -e ; \
	rm -rf build ; \
	mkdir build ; \
	cd build ; \
	../configure \
		--host=$(CONFIGURE_HOST) \
		--prefix=$(ROMFSDIR)/usr

clean:
	rm -rf build DESTDIR

%::
	if [ -f Makefile ] ; then $(MAKE) -f Makefile $@ || exit $$? ; fi

romfs:
	$(ROMFSINST) build/strace /bin/
	$(ROMFSINST) -e CONFIG_USER_PERL_PERL build/strace-graph /bin/
