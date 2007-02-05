ifeq ($(CONFIG_FMT_USE_FLAT)$(CONFIG_FMT_USE_SHARED_FLAT),)
ADNS_CONF_OPTS = --enable-dynamic
else
ADNS_CONF_OPTS = --disable-dynamic
endif

all: build/Makefile
	$(MAKE) -C build

build/Makefile: Makefile
	find . -type f -print0 | xargs -0 touch -r configure
	set -e ; \
	rm -rf build ; \
	mkdir build ; \
	cd build ; \
	../configure $(CONFIGURE_OPTS) $(ADNS_CONF_OPTS)

romfs:
	#$(ROMFSINST) build/client/adnshost /bin/adnshost
ifeq ($(CONFIG_FMT_USE_FLAT)$(CONFIG_FMT_USE_SHARED_FLAT),)
	$(ROMFSINST) build/dynamic/libadns.so.1.0 /lib/libadns.so.1.0
	$(ROMFSINST) -s libadns.so.1.0 /lib/libadns.so.1
	$(ROMFSINST) -s libadns.so.1.0 /lib/libadns.so
endif

clean:
	rm -rf build

.PHONY: all clean romfs
