all: build/Makefile
ifeq ($(CONFIG_FMT_USE_FDPIC_ELF),y)
	$(MAKE) -C build install DESTDIR=$(STAGEDIR)
	cp etc/ts.conf $(STAGEDIR)/usr/lib/ts/ts.conf
endif

build/Makefile:
ifeq ($(CONFIG_FMT_USE_FDPIC_ELF),y)
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
endif

clean:
	rm -rf build

romfs:
ifeq ($(CONFIG_FMT_USE_FDPIC_ELF),y)
	$(ROMFSINST) $(STAGEDIR)/usr/lib/libts.so /lib/
	$(ROMFSINST) $(STAGEDIR)/usr/lib/libts-0.0.so.0 /lib/
	$(ROMFSINST) $(STAGEDIR)/usr/lib/ts/dejitter.so /lib/
	$(ROMFSINST) $(STAGEDIR)/usr/lib/ts/input.so /lib/
	$(ROMFSINST) $(STAGEDIR)/usr/lib/ts/linear.so /lib/
	$(ROMFSINST) $(STAGEDIR)/usr/lib/ts/pthres.so /lib/
	$(ROMFSINST) $(STAGEDIR)/usr/lib/ts/variance.so /lib/
	$(ROMFSINST) $(STAGEDIR)/usr/bin/ts_calibrate /bin/
	$(ROMFSINST) $(STAGEDIR)/usr/lib/ts/ts.conf /etc/
endif

.PHONY: all clean romfs
