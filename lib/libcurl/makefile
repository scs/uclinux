CONFOPTS :=	--enable-dependency-tracking \
		--disable-largefile \
		--enable-http \
		--enable-ftp \
		--enable-gopher \
		--enable-file \
		--disable-ldap \
		--enable-dict \
		--enable-telnet \
		--enable-manual \
		--enable-ipv6 \
		--enable-nonblocking \
		--disable-thread \
		--disable-ares \
		--enable-verbose \
		--disable-sspi \
		--enable-debug \
		--enable-crypto-auth \
		--enable-cookies \
		--with-random=/dev/urandom \
		--with-ssl=$(ROOTDIR)/lib/libssl \
		--with-zlib=$(ROOTDIR)/lib/zlib \
		--with-libidn=$(ROOTDIR)/lib/libidn

all: build/build
	$(MAKE) -C build
	-chmod u+x build/curl-config

build/build: makefile
	@chmod u+x configure
	@rm -rf build
	@mkdir build
	(cd build; sh ../configure $(CONFIGURE_OPTS) $(CONFOPTS))
	@touch build/build

clean:
	rm -rf build

romfs:
