#PROGRAMS="dropbear dbclient dropbearkey dropbearconvert scp"
all: build/Makefile
	$(MAKE) -C build MULTI=1

build/Makefile:
	touch *
	set -e ; \
	rm -rf build ; \
	mkdir build ; \
	cd build ; \
	../configure $(CONFIGURE_OPTS)

	# work around broken libtom makefiles
	set -e ; \
	list=`cd libtomcrypt ; find . -mindepth 1 -type d` ; \
	cd build/libtomcrypt ; \
	mkdir -p $$list

clean:
	rm -rf build

romfs:
	$(ROMFSINST) -e CONFIG_USER_DROPBEAR_DROPBEAR build/dropbearmulti /bin/dropbear
	$(ROMFSINST) -e CONFIG_USER_DROPBEAR_DROPBEAR -s dropbear /bin/dropbearkey
	$(ROMFSINST) -e CONFIG_USER_DROPBEAR_DROPBEAR -s dropbear /bin/dbclient
	$(ROMFSINST) -e CONFIG_USER_DROPBEAR_DROPBEAR -s dropbear /bin/dropbearconvert
	#$(ROMFSINST) -e CONFIG_USER_DROPBEAR_DROPBEAR -s dropbear /bin/dbscp
	$(ROMFSINST) -e CONFIG_USER_DROPBEAR_DROPBEAR \
		-a "ssh     stream tcp nowait root /bin/dropbear -i 2 > /dev/null" /etc/inetd.conf

.PHONY: all clean romfs
