VER = alsa-lib-1.0.12

# we need to separate the build/install steps as the
# install commands do not do proper dependency checking
all: build-$(VER)/Makefile
	$(MAKE) -C build-$(VER)
	$(MAKE) -C build-$(VER) install DESTDIR=$(STAGEDIR)

build-$(VER)/Makefile:
	find $(VER) -type f -print0 | xargs -0 touch -r $(VER)/configure
	set -e ; \
	rm -rf build-$(VER) ; \
	mkdir build-$(VER) ; \
	cd build-$(VER) ; \
	../$(VER)/configure \
		$(CONFIGURE_OPTS) \
		--with-softfloat \
		--with-versioned=no

clean:
	rm -rf build*

romfs:
	if [ "$(CONFIG_LIB_ALSA_LIB)" = "y" ] || [ "$(CONFIG_LIB_ALSA_LIB_FORCE)" = "y" ] ; then \
		for conf in `cd $(STAGEDIR) ; find usr/share/alsa -type f` ; do \
			$(ROMFSINST) -d $(STAGEDIR)/$$conf /$$conf || exit $$? ; \
		done ; \
	fi
	$(ROMFSINST) \
		-d -e CONFIG_FMT_USE_FDPIC_ELF \
		$(STAGEDIR)/usr/lib/libasound.so.2 \
		/usr/lib/libasound.so.2

.PHONY: all clean romfs
