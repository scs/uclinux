all: build/Makefile
	$(MAKE) -C build install DESTDIR=$(STAGEDIR)

build/Makefile:
	find . -type f -print0 | xargs -0 touch -r configure
	set -e ; \
	rm -rf build ; \
	mkdir build ; \
	cd build ; \
	../configure $(CONFIGURE_OPTS)

clean:
	rm -rf build

romfs:
	cd $(STAGEDIR)/usr/bin && \
		$(ROMFSINST) -e CONFIG_USER_LIBIPOD_EXAMPLES dumptracks dumptracks_cpp readwritedb teststrings /bin
	$(ROMFSINST) -e CONFIG_FMT_USE_FDPIC_ELF $(STAGEDIR)/usr/lib/libipod.so.0 /lib/

.PHONY: all clean romfs
