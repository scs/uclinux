all: build/Makefile
	$(MAKE) -C build install DESTDIR=$(STAGEDIR)
	rm -f $(STAGEDIR)/usr/lib/*.old

build/Makefile:
	touch * */*
	set -e ; \
	rm -rf build ; \
	mkdir build ; \
	cd build ; \
	CROSS_COMPILE="" ../configure $(CONFIGURE_OPTS)

clean:
	rm -rf build

romfs:
ifeq ($(CONFIG_FMT_USE_FDPIC_ELF),y)
	mv $(DESTDIR)/usr/lib/libreadline.so* $(ROMFSDIR)/lib/
endif

.PHONY: all clean romfs
