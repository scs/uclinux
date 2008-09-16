VER = openssl-0.9.8g

ifeq ($(CONFIG_FMT_USE_FDPIC_ELF),y)
SSL_SHARED := shared
else
SSL_SHARED := no-dso
endif

SSL_OPTS = \
	DIRS="crypto ssl engines" \
	CC=$(CONFIGURE_HOST)-gcc

all: $(VER)/Makefile.bak
	$(MAKE) -C $(VER) $(SSL_OPTS)
	$(MAKE) -C $(VER) $(SSL_OPTS) install_sw INSTALL_PREFIX=$(STAGEDIR)

$(VER)/Makefile.bak:
	set -e ; \
	cd $(VER) ; \
	./Configure \
		linux-generic32 -DL_ENDIAN \
		--prefix=/usr \
		--openssldir=/etc/ssl \
		$(SSL_SHARED) threads

clean:
	rm -f $(VER)/Makefile.bak
	$(MAKE) -C $(VER) clean

romfs:
	$(ROMFSINST) -d -e CONFIG_FMT_USE_FDPIC_ELF $(STAGEDIR)/usr/lib/libssl.so.0.9.8 /usr/lib/libssl.so.0.9.8
	$(ROMFSINST) -d -e CONFIG_FMT_USE_FDPIC_ELF $(STAGEDIR)/usr/lib/libcrypto.so.0.9.8 /usr/lib/libcrypto.so.0.9.8

.PHONY: all clean romfs
