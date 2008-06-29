ifeq ($(MAKECMDGOALS)$(CONFIG_FMT_USE_FDPIC_ELF),)
$(warning )
$(warning )
$(warning tslib only works with FDPIC, please change your build settings from FLAT to FDPIC)
$(warning )
$(warning )
$(error )
endif

all: build/Makefile
	$(MAKE) -C build install DESTDIR=$(STAGEDIR)
	cp etc/ts.conf $(STAGEDIR)/usr/lib/ts/ts.conf

build/Makefile:
	find . -type f -print0 | xargs -0 touch -r configure
	set -e ; \
	rm -rf build ; \
	mkdir build ; \
	cd build ; \
	../configure \
		$(CONFIGURE_OPTS) \
		--disable-h2200-linear \
		--disable-ucb1x00 \
		--disable-corgi \
		--disable-collie \
		--disable-h3600 \
		--disable-mk712 \
		--disable-arctic2 \
		CFLAGS='-DUSE_INPUT_API' 

clean:
	rm -rf build

romfs:
	$(ROMFSINST) -d $(STAGEDIR)/usr/lib/libts-0.0.so.0 /usr/lib/libts-0.0.so.0
	$(ROMFSINST) -d $(STAGEDIR)/usr/lib/ts/dejitter.so /usr/lib/ts/dejitter.so
	$(ROMFSINST) -d $(STAGEDIR)/usr/lib/ts/input.so /usr/lib/ts/input.so
	$(ROMFSINST) -d $(STAGEDIR)/usr/lib/ts/linear.so /usr/lib/ts/linear.so
	$(ROMFSINST) -d $(STAGEDIR)/usr/lib/ts/pthres.so /usr/lib/ts/pthres.so
	$(ROMFSINST) -d $(STAGEDIR)/usr/lib/ts/variance.so /usr/lib/variance.so
	$(ROMFSINST) -d $(STAGEDIR)/usr/bin/ts_calibrate /usr/bin/ts_calibrate
	$(ROMFSINST) -d $(STAGEDIR)/usr/lib/ts/ts.conf /etc/ts.conf

.PHONY: all clean romfs
