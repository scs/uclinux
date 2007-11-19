VER = openntpd-3.9p1

all: build-$(VER)/Makefile
	$(MAKE) -C build-$(VER)

build-$(VER)/Makefile:
	find $(VER) -type f -print0 | xargs -0 touch -r $(VER)/configure
	set -e ; \
	rm -rf build-$(VER) ; \
	mkdir build-$(VER) ; \
	cd build-$(VER) ; \
	../$(VER)/configure \
		$(CONFIGURE_OPTS) \
		--disable-strip

clean:
	rm -rf build-*

romfs:
	$(ROMFSINST) -d build-$(VER)/ntpd /usr/bin/ntpd

.PHONY: all clean romfs
