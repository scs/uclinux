all: build/Makefile
	$(MAKE) -C build MULTI=1

CFLAGS += -I$(ROOTDIR)/lib/zlib
build/Makefile:
	touch *
	set -e ; \
	rm -rf build ; \
	mkdir build ; \
	cd build ; \
	../configure \
		--host=$(CONFIGURE_HOST) \
		--prefix=/usr \
		--with-zlib=$(ROOTDIR)/lib/zlib

	# work around broken libtom makefiles
	set -e ; \
	list=`cd libtomcrypt ; find . -mindepth 1 -type d` ; \
	cd build/libtomcrypt ; \
	mkdir $$list

clean:
	rm -rf build DESTDIR

%::
	if [ -f build/Makefile ] ; then $(MAKE) -C build -f Makefile $@ || exit $$? ; fi

romfs:
	$(ROMFSINST) -e CONFIG_USER_DROPBEAR_DROPBEAR build/dropbearmulti /bin/dropbear
	$(ROMFSINST) -e CONFIG_USER_DROPBEAR_DROPBEAR -s dropbear /bin/dropbearkey
	$(ROMFSINST) -e CONFIG_USER_DROPBEAR_DROPBEAR -s dropbear /bin/dbclient
	$(ROMFSINST) -e CONFIG_USER_DROPBEAR_DROPBEAR \
		-a "ssh     stream tcp nowait root /bin/dropbear -i 2 > /dev/null" /etc/inetd.conf

.PHONY: all clean distclean romfs
