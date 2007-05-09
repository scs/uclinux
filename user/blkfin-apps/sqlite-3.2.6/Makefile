all: build/Makefile
	$(MAKE) -C build install DESTDIR=$$PWD/DESTDIR

build/Makefile:
	find . -type f -print0 | xargs -0 touch -r configure
	set -e ; \
	rm -rf build ; \
	mkdir build ; \
	cd build ; \
	../configure \
		$(CONFIGURE_OPTS) \
		--disable-tcl
	# sqlite has a completely retarded build system; while it
	# gets fixed upstream, workaround it in this version
	sed -i \
		-e '/^READLINE_FLAGS =/s:=.*:=:' \
		-e '/^LIBREADLINE =/s:=.*:=:' \
		build/Makefile

clean:
	rm -rf build DESTDIR

romfs:
	$(ROMFSINST) DESTDIR/usr/bin/sqlite3 /bin/sqlite3
	$(ROMFSINST) -e CONFIG_FMT_USE_FDPIC_ELF DESTDIR/usr/lib/libsqlite3.so.0 /lib/

.PHONY: all clean romfs
