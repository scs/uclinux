all: my-build/Makefile
	$(MAKE) -C my-build install DESTDIR=$(STAGEDIR)

my-build/Makefile:
	find . -type f -print0 | xargs -0 touch -r configure
	set -e ; \
	rm -rf my-build ; \
	mkdir my-build ; \
	cd my-build ; \
	../configure \
		$(CONFIGURE_OPTS) \
		--enable-samples

clean:
	rm -rf my-build

romfs:
	$(ROMFSINST) -e CONFIG_USER_UPNP_SAMPLES my-build/upnp/upnp_tv_ctrlpt /bin/
	$(ROMFSINST) -e CONFIG_USER_UPNP_SAMPLES my-build/upnp/upnp_tv_device /bin/
	$(ROMFSINST) -e CONFIG_USER_UPNP_SAMPLES upnp/sample/tvdevice/web /web/

.PHONY: all clean romfs
