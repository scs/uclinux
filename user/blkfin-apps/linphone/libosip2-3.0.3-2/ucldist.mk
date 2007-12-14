OSIP2_FLAGS+=--disable-shared
OSIP2_FLAGS+=--enable-static

all: build/Makefile
	$(MAKE) -C build install

build/Makefile:
	touch *
	set -e ; \
	rm -rf build ; \
	mkdir build ; \
	cd build ; \
	../configure \
		--host=$(CONFIGURE_HOST) \
		--prefix=$(TEMPDIR) \
		$(OSIP2_FLAGS) CC="$(CC)"

clean:
	rm -rf build
