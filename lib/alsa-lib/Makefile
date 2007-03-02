all: build/Makefile
	$(MAKE) -C build -f Makefile install DESTDIR=$(STAGEDIR)

build/Makefile:
	find . -type f -print0 | xargs -0 touch -r configure
	set -e ; \
	rm -rf build ; \
	mkdir build ; \
	cd build ; \
	../configure \
		--host=$(CONFIGURE_HOST) \
		--build=$(CONFIGURE_BUILD) \
		--target=$(CONFIGURE_HOST) \
		--prefix=/usr/local \
		--with-softfloat \
		--with-versioned=no

clean:
	rm -rf build

romfs:
	if [ "$(CONFIG_LIB_ALSA_LIB)" = "y" ] || [ "$(CONFIG_LIB_ALSA_LIB_FORCE)" = "y" ] ; then \
		for conf in `cd $(STAGEDIR) ; find usr/local/share/alsa -type f` ; do \
			$(ROMFSINST) -d $(STAGEDIR)/$$conf /$$conf || exit $$? ; \
		done ; \
	fi
	$(ROMFSINST) \
		-e CONFIG_FMT_USE_FDPIC_ELF \
		$(STAGEDIR)/usr/local/lib/libasound.so.2 \
		/lib/

.PHONY: all clean romfs
