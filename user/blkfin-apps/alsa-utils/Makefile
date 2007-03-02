all: build/Makefile
	$(MAKE) -C build -f Makefile install DESTDIR=$$PWD/DESTDIR

build/Makefile:
	find . -type f -print0 | xargs -0 touch -r configure
	set -e ; \
	rm -rf build ; \
	mkdir build ; \
	cd build ; \
	../configure \
		$(CONFIGURE_OPTS) \
		--with-alsa-prefix=$(STAGEDIR)/usr/local/lib \
		--with-alsa-inc-prefix=$(STAGEDIR)/usr/local/include

clean:
	rm -rf build DESTDIR

romfs:
	for bin in `cd DESTDIR ; ls usr/bin/* usr/sbin/*` ; do \
		if echo "$$bin" | grep -e "arecord$$" > /dev/null ; then \
			$(ROMFSINST) -s /usr/bin/aplay /$$bin ; \
		else \
			$(ROMFSINST) -d -e CONFIG_USER_ALSA_UTILS DESTDIR/$$bin /$$bin || exit $$? ; \
		fi ; \
	done

.PHONY: all clean romfs
