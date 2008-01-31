VER = sqlite-3.5.5

all: build-$(VER)/Makefile
	$(MAKE) -C build-$(VER) install DESTDIR=$(STAGEDIR)

build-$(VER)/Makefile:
	find $(VER) -type f -print0 | xargs -0 touch -r $(VER)/configure
	set -e ; \
	rm -rf build-$(VER) ; \
	mkdir build-$(VER) ; \
	cd build-$(VER) ; \
	../$(VER)/configure \
		$(CONFIGURE_OPTS) \
		--disable-tcl

ifeq ($(VER),sqlite-3.2.6)
	# sqlite has a completely retarded build system; while it
	# gets fixed upstream, workaround it in this version
	sed -i \
		-e '/^READLINE_FLAGS =/s:=.*:=:' \
		-e '/^LIBREADLINE =/s:=.*:=:' \
		build-$(VER)/Makefile
endif

clean:
	rm -rf build-$(VER) DESTDIR-$(VER)

romfs:
	$(ROMFSINST) $(STAGEDIR)/usr/bin/sqlite3 /bin/sqlite3
	$(ROMFSINST) -e CONFIG_FMT_USE_FDPIC_ELF $(STAGEDIR)/usr/lib/libsqlite3.so.0 /lib/

.PHONY: all clean romfs
