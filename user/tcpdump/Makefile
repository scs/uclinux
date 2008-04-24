VER = tcpdump-3.9.8

CONF_OPTS = --with-crypto --disable-smb
ifdef CONFIG_IPV6
CONF_OPTS += --enable-ipv6
endif

export ac_cv_linux_vers=2
export ac_cv_lbl_unaligned_fail=yes

include $(ROOTDIR)/tools/autotools.mk

romfs:
	$(ROMFSINST) -d $(STAGEDIR)/usr/sbin/tcpdump /usr/sbin/tcpdump
