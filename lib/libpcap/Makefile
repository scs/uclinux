VER = libpcap-0.9.8

CONF_OPTS = --with-pcap=linux
ifdef CONFIG_IPV6
CONF_OPTS += --enable-ipv6
endif

export ac_cv_linux_vers=2
export ac_cv_lbl_unaligned_fail=yes

include $(ROOTDIR)/tools/autotools.mk

ifeq ($(CONFIG_FMT_USE_FDPIC_ELF),y)
post-build::
	$(MAKE) -C build-$(VER) install-shared DESTDIR=$(STAGEDIR)
endif

romfs:
	$(ROMFSINST) -d -e CONFIG_FMT_USE_FDPIC_ELF $(STAGEDIR)/usr/lib/libpcap.so.0 /usr/lib/libpcap.so.0
