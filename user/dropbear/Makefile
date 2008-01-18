all: build/Makefile build-host/Makefile
	$(MAKE) -C build MULTI=1 PROGRAMS="dropbear dbclient dropbearkey dropbearconvert scp"
	$(MAKE) -C build-host dropbearkey

build/Makefile:
	find . -type f -print0 | xargs -0 touch -r configure
	set -e ; \
	rm -rf build ; \
	mkdir build ; \
	cd build ; \
	../configure $(CONFIGURE_OPTS)

	# work around broken libtom makefiles
	set -e ; \
	list=`find libtom* -mindepth 1 -type d` ; \
	cd build ; \
	mkdir -p $$list

build-host/Makefile:
	find . -type f -print0 | xargs -0 touch -r configure
	set -e ; \
	rm -rf build-host ; \
	mkdir build-host ; \
	cd build-host ; \
	unset AR CC LD RANLIB CFLAGS LDFLAGS CPPFLAGS ; \
	../configure

	# work around broken libtom makefiles
	set -e ; \
	list=`find libtom* -mindepth 1 -type d` ; \
	cd build-host ; \
	mkdir -p $$list

clean:
	rm -rf build build-host

romfs:
	$(ROMFSINST) build/dropbearmulti /bin/dropbear
	$(ROMFSINST) -s dropbear /bin/dropbearkey
	$(ROMFSINST) -s dropbear /bin/dbclient
	$(ROMFSINST) -s dropbear /bin/dropbearconvert
	$(ROMFSINST) -s dropbear /bin/scp
	$(ROMFSINST) -a "ssh     stream tcp nowait root /bin/dropbear -i 2 > /dev/null" /etc/inetd.conf

	mkdir -p $(ROMFSDIR)/etc/dropbear
	[ -e $(ROMFSDIR)/etc/dropbear/dropbear_dss_host_key ] || ./build-host/dropbearkey -t dss -f $(ROMFSDIR)/etc/dropbear/dropbear_dss_host_key
	[ -e $(ROMFSDIR)/etc/dropbear/dropbear_rsa_host_key ] || ./build-host/dropbearkey -t rsa -f $(ROMFSDIR)/etc/dropbear/dropbear_rsa_host_key

.PHONY: all clean romfs
