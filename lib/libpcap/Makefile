VER = libpcap-0.9.8

CONF_OPTS = --with-pcap=linux
ifdef CONFIG_IPV6
CONF_OPTS += --enable-ipv6
endif

all: build-$(VER)/Makefile
	$(MAKE) -C build-$(VER) install DESTDIR=$(STAGEDIR)

build-$(VER)/Makefile:
	find $(VER) -type f -print0 | xargs -0 touch -r $(VER)/configure
	set -e ; \
	rm -rf build-$(VER) ; \
	mkdir build-$(VER) ; \
	cd build-$(VER) ; \
	ac_cv_linux_vers=2 \
	ac_cv_lbl_unaligned_fail=yes \
	../$(VER)/configure $(CONFIGURE_OPTS) $(CONF_OPTS)

clean:
	rm -rf build*

romfs:

.PHONY: all clean romfs
