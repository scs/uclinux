VER = curl-7.17.1

CONF_OPTS = --with-random=/dev/urandom

# upstream's install targets lack dependencies on the things
# they install, so just decouple build/install steps
all: build-$(VER)/Makefile
	$(MAKE) -C build-$(VER)
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
	$(ROMFSINST) -d -e CONFIG_FMT_USE_FDPIC_ELF $(STAGEDIR)/usr/lib/libcurl.so.4 /usr/lib/libcurl.so.4
	$(ROMFSINST) -d -e CONFIG_USER_CURL_CURL $(STAGEDIR)/usr/bin/curl /usr/bin/curl

.PHONY: all clean romfs
