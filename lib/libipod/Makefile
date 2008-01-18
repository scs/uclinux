VER = libipod-0.1

all: build-$(VER)/Makefile
	$(MAKE) -C build-$(VER) install DESTDIR=$(STAGEDIR)

build-$(VER)/Makefile:
	find $(VER) -type f -print0 | xargs -0 touch -r $(VER)/configure
	set -e ; \
	rm -rf build-$(VER) ; \
	mkdir build-$(VER) ; \
	cd build-$(VER) ; \
	../$(VER)/configure $(CONFIGURE_OPTS)

clean:
	rm -rf build*

romfs:
	set -e ; \
	for x in dumptracks dumptracks_cpp readwritedb teststrings ; do \
		$(ROMFSINST) -e CONFIG_USER_LIBIPOD_EXAMPLES build-$(VER)/examples/.libs/$$x /bin/$$x ; \
	done
	$(ROMFSINST) -e CONFIG_FMT_USE_FDPIC_ELF $(STAGEDIR)/usr/lib/libipod.so.0 /lib/

.PHONY: all clean romfs
