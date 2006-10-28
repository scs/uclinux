all: build/Makefile
	$(MAKE) -C build -f Makefile install DESTDIR=$$PWD/DESTDIR

build/Makefile:
	touch * */*
	set -e ; \
	rm -rf build ; \
	mkdir build ; \
	cd build ; \
	LDFLAGS="-L$(ROOTDIR)/lib/ncurses/lib $(LDFLAGS)" \
	CPPFLAGS="-I$(ROOTDIR)/lib/ncurses/include $(CPPFLAGS)" \
	../configure \
		--host=bfin-uclinux \
		--prefix=/usr \
		--with-alsa-prefix=$(ROOTDIR)/lib/alsa-lib/DESTDIR/usr/lib \
		--with-alsa-inc-prefix=$(ROOTDIR)/lib/alsa-lib/DESTDIR/usr/include

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
