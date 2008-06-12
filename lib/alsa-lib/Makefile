ifeq ($(MAKECMDGOALS)$(CONFIG_FMT_USE_FDPIC_ELF),)
$(warning )
$(warning )
$(warning alsa-lib only works with FDPIC, please change your build settings from FLAT to FDPIC)
$(warning )
$(warning )
$(error )
endif

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
	$(ROMFSINST) -d $(STAGEDIR)/usr/share/alsa /usr/share/alsa
	$(ROMFSINST) -d -e CONFIG_FMT_USE_FDPIC_ELF $(STAGEDIR)/usr/lib/libasound.so.2 /usr/lib/libasound.so.2
	$(ROMFSINST) -E CONFIG_SND_MMAP_SUPPORT $(VER)/src/conf/cards/AD1980-no-mmap.conf /usr/share/alsa/cards/AD1980.conf
	$(ROMFSINST) -E CONFIG_SND_MMAP_SUPPORT $(VER)/src/conf/cards/SSM2602-no-mmap.conf /usr/share/alsa/cards/SSM2602.conf
.PHONY: all clean romfs
