VER = libeXosip2-3.0.3-3

all: build-$(VER)/Makefile
	$(MAKE) -C build-$(VER) install DESTDIR=$(STAGEDIR)

build-$(VER)/Makefile:
	find $(VER) -type f -print0 | xargs -0 touch -r $(VER)/configure
	set -e ; \
	rm -rf build-$(VER) ; \
	mkdir build-$(VER) ; \
	cd build-$(VER) ; \
	../$(VER)/configure \
		$(CONFIGURE_OPTS)

	# stupid build system: submitted bugs upstream already
	sed -i \
		-e '/^INCLUDES =/s:-I$$(includedir)::' \
		-e '/^INCLUDES =/s:-I$$(prefix)/include::' \
		-e '/LDFLAGS/s:-L$$(prefix)/lib::' \
		-e '/LDADD/s:-L$$(prefix)/lib::' \
		build-$(VER)/*/Makefile

clean:
	rm -rf build-$(VER)

romfs:
	$(ROMFSINST) -d -e CONFIG_FMT_USE_FDPIC_ELF $(STAGEDIR)/usr/lib/libeXosip2.so.4 /usr/lib/libeXosip2.so.4

.PHONY: all clean romfs
