all: build/Makefile
	$(MAKE) -C build

build/Makefile:
	touch ../*/*
	set -e ; \
	rm -rf build ; \
	mkdir build ; \
	cd build ; \
	../configure \
		--host=$(CONFIGURE_HOST) \
		--prefix=/usr

clean:
	rm -rf build DESTDIR

%::
	if [ -f build/Makefile ] ; then $(MAKE) -C build -f Makefile $@ || exit $$? ; fi

romfs:
	$(ROMFSINST) -e CONFIG_USER_GDBSERVER_GDBSERVER	build/gdbserver /bin/gdbserver
	$(ROMFSINST) -e CONFIG_USER_GDBSERVER_GDBREPLAY	build/gdbreplay /bin/gdbreplay

.PHONY: all clean distclean romfs
