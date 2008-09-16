VER = btsco-0.5

all: build-$(VER)/Makefile
	$(MAKE) -C build-$(VER)

build-$(VER)/Makefile:
	find $(VER) -type f -print0 | xargs -0 touch -r $(VER)/configure
	set -e ; \
	rm -rf build-$(VER) ; \
	mkdir build-$(VER) ; \
	cd build-$(VER) ; \
	../$(VER)/configure $(CONFIGURE_OPTS) \
	--enable-alsaplugin \
	LDFLAGS="$(LDFLAGS) -L$(ROOTDIR)/user/blkfin-apps/btsco/build-$(VER)/sbc/" \
	--with-bluez=$(STAGEDIR) \
	--with-alsa-inc-prefix=$(STAGEDIR)/usr/include \
	--with-alsa-prefix=$(STAGEDIR)/usr/lib

clean:
	rm -rf build*

romfs:
	$(ROMFSINST) -d build-$(VER)/alsa-plugins/headsetd/headsetd /usr/bin/headsetd
	$(ROMFSINST) -d build-$(VER)/alsa-plugins/a2dpd /usr/bin/a2dpd
	cp -d build-$(VER)/alsa-plugins/.libs/libasound_module*.so* $(ROMFSDIR)/usr/lib/

.PHONY: all clean romfs
