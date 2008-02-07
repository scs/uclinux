VER = tcpdump-3.9.8

CONF_OPTS = --with-crypto --disable-smb
ifdef CONFIG_IPV6
CONF_OPTS += --enable-ipv6
endif

all: build-$(VER)/Makefile
	$(MAKE) -C build-$(VER)

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
	$(ROMFSINST) -d build-$(VER)/tcpdump /usr/bin/tcpdump

.PHONY: all clean romfs
