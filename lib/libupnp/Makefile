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
		--prefix=/usr \
		--enable-samples

clean:
	rm -rf build DESTDIR

%::
	if [ -f build/Makefile ] ; then $(MAKE) -C build -f Makefile $@ || exit $$? ; fi

romfs:
	$(ROMFSINST) -e CONFIG_USER_UPNP_SAMPLES build/upnp/upnp_tv_ctrlpt /bin/
	$(ROMFSINST) -e CONFIG_USER_UPNP_SAMPLES build/upnp/upnp_tv_device /bin/
	$(ROMFSINST) -e CONFIG_USER_UPNP_SAMPLES upnp/sample/tvdevice/web /web/
