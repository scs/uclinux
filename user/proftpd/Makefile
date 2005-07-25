#
# build using configure as best we can, should work for most targets
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
		../configure --host $(CROSS_COMPILE:-=) --enable-cap --with-libraries=$(ROOTDIR)/user/proftpd/build/lib --prefix= ; \
	)
	mkdir build/lib/libcap
	cp lib/libcap/Makefile build/lib/libcap/

romfs:
	$(ROMFSINST) build/proftpd /bin/

clean:
	rm -rf build

