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
	$(ROMFSINST) $(STAGEDIR)/usr/lib/libts.so /lib/
	$(ROMFSINST) $(STAGEDIR)/usr/lib/libts-0.0.so.0 /lib/
	$(ROMFSINST) $(STAGEDIR)/usr/lib/ts/dejitter.so /lib/
	$(ROMFSINST) $(STAGEDIR)/usr/lib/ts/input.so /lib/
	$(ROMFSINST) $(STAGEDIR)/usr/lib/ts/linear.so /lib/
	$(ROMFSINST) $(STAGEDIR)/usr/lib/ts/pthres.so /lib/
	$(ROMFSINST) $(STAGEDIR)/usr/lib/ts/variance.so /lib/
	$(ROMFSINST) $(STAGEDIR)/usr/bin/ts_calibrate /bin/
	$(ROMFSINST) $(STAGEDIR)/usr/lib/ts/ts.conf /etc/

.PHONY: all clean romfs
