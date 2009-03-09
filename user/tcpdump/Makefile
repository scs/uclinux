VER = tcpdump-4.0.0
URL = http://www.tcpdump.org/release/$(VER).tar.gz

CONF_OPTS = \
	--disable-smb \
	$(call USE_WITH,LIB_LIBSSL,crypto,$(STAGEDIR)/usr) \
	$(call USE_ENABLE,IPV6,ipv6)

export ac_cv_linux_vers=2
export ac_cv_lbl_unaligned_fail=yes

include $(ROOTDIR)/tools/autotools.mk

romfs:
	$(ROMFSINST) -d $(STAGEDIR)/usr/sbin/tcpdump /usr/sbin/tcpdump
