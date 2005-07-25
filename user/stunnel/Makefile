#
# build using configure as best we can, should work for most targets
# David McCullough <davidm@snapgear.com>
#

all: build
	$(MAKE) -C build

build: Makefile
	rm -rf build
	mkdir build
	chmod u+x configure
	( \
		cd build; \
		export CC="$(CC) $(CFLAGS)"; \
		export LDFLAGS="$(LDFLAGS)"; \
		export LIBS="$(LDLIBS)"; \
		../configure --with-ssl=$(ROOTDIR) --host $(CROSS_COMPILE:-=) --with-random=/dev/urandom \
			--prefix= ; \
	)

romfs:
	$(ROMFSINST) build/src/stunnel /bin/stunnel
ifdef CONFIG_USER_FLATFSD_FLATFSD
	$(ROMFSINST) -s /etc/config /etc/stunnel
endif

clean:
	rm -rf build

