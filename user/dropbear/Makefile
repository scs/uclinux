VER = dropbear-0.52

FLTFLAGS = -s 0x4000

export MULTI = 1
export PROGRAMS = dropbear dbclient dropbearkey dropbearconvert scp

AUTOTOOLS_BUILD_HOST = true

include $(ROOTDIR)/tools/autotools.mk

pre-build::
	$(MAKE) -C build-$(VER)

host-build:
	$(MAKE) -C build-host-$(VER) dropbearkey MULTI=0

romfs:
	$(ROMFSINST) -d build-$(VER)/dropbearmulti /usr/bin/dropbear
	$(ROMFSINST) -s dropbear /usr/bin/dropbearkey
	$(ROMFSINST) -s dropbear /usr/bin/dbclient
	$(ROMFSINST) -s dropbear /usr/bin/dropbearconvert
	$(ROMFSINST) -s dropbear /usr/bin/scp
	$(ROMFSINST) -a "ssh     stream tcp nowait root /usr/bin/dropbear -i 2 > /dev/null" /etc/inetd.conf

	mkdir -p $(ROMFSDIR)/etc/dropbear
	[ -e $(ROMFSDIR)/etc/dropbear/dropbear_dss_host_key ] || ./build-host-$(VER)/dropbearkey -t dss -f $(ROMFSDIR)/etc/dropbear/dropbear_dss_host_key
	[ -e $(ROMFSDIR)/etc/dropbear/dropbear_rsa_host_key ] || ./build-host-$(VER)/dropbearkey -t rsa -f $(ROMFSDIR)/etc/dropbear/dropbear_rsa_host_key
