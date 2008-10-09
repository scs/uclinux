VER = dropbear-0.51

FLTFLAGS = -s 0x4000

all: build-$(VER)/Makefile build-$(VER)-host/dropbearkey
	$(MAKE) -C build-$(VER) MULTI=1 PROGRAMS="dropbear dbclient dropbearkey dropbearconvert scp"

build-$(VER)-host/dropbearkey: build-$(VER)-host/Makefile
	$(MAKE) -C build-$(VER)-host dropbearkey

build-$(VER)/Makefile:
	find $(VER) -type f -print0 | xargs -0 touch -r $(VER)/configure
	set -e ; \
	rm -rf build-$(VER) ; \
	mkdir build-$(VER) ; \
	cd build-$(VER) ; \
	../$(VER)/configure $(CONFIGURE_OPTS)

build-$(VER)-host/Makefile:
	find $(VER) -type f -print0 | xargs -0 touch -r $(VER)/configure
	set -e ; \
	rm -rf build-$(VER)-host ; \
	mkdir build-$(VER)-host ; \
	cd build-$(VER)-host ; \
	unset AR CC LD RANLIB CFLAGS LDFLAGS CPPFLAGS ; \
	../$(VER)/configure

clean:
	rm -rf build*

romfs:
	$(ROMFSINST) -d build-$(VER)/dropbearmulti /usr/bin/dropbear
	$(ROMFSINST) -s dropbear /usr/bin/dropbearkey
	$(ROMFSINST) -s dropbear /usr/bin/dbclient
	$(ROMFSINST) -s dropbear /usr/bin/dropbearconvert
	$(ROMFSINST) -s dropbear /usr/bin/scp
	$(ROMFSINST) -a "ssh     stream tcp nowait root /usr/bin/dropbear -i 2 > /dev/null" /etc/inetd.conf

	mkdir -p $(ROMFSDIR)/etc/dropbear
	[ -e $(ROMFSDIR)/etc/dropbear/dropbear_dss_host_key ] || ./build-$(VER)-host/dropbearkey -t dss -f $(ROMFSDIR)/etc/dropbear/dropbear_dss_host_key
	[ -e $(ROMFSDIR)/etc/dropbear/dropbear_rsa_host_key ] || ./build-$(VER)-host/dropbearkey -t rsa -f $(ROMFSDIR)/etc/dropbear/dropbear_rsa_host_key

.PHONY: all clean romfs
