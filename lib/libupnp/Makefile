VER = libupnp-1.4.6

CONF_OPTS = --enable-samples

all: build-$(VER)/Makefile
	$(MAKE) -C build-$(VER) install DESTDIR=$(STAGEDIR)

build-$(VER)/Makefile:
	find $(VER) -type f -print0 | xargs -0 touch -r $(VER)/configure
	set -e ; \
	rm -rf build-$(VER) ; \
	mkdir build-$(VER) ; \
	cd build-$(VER) ; \
	../$(VER)/configure $(CONFIGURE_OPTS) $(CONF_OPTS)

clean:
	rm -rf build*

romfs:
	$(ROMFSINST) -d -e CONFIG_FMT_USE_FDPIC_ELF $(STAGEDIR)/usr/lib/libupnp.so.2 /usr/lib/libupnp.so.2
	$(ROMFSINST) -e CONFIG_USER_UPNP_SAMPLES my-build/upnp/upnp_tv_ctrlpt /bin/
	$(ROMFSINST) -e CONFIG_USER_UPNP_SAMPLES my-build/upnp/upnp_tv_device /bin/
	$(ROMFSINST) -e CONFIG_USER_UPNP_SAMPLES upnp/sample/tvdevice/web /web/

.PHONY: all clean romfs
