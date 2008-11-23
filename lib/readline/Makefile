VER = readline-5.2_p13

CONF_OPTS = $(CONFIGURE_SHARED_ENABLE)

include $(ROOTDIR)/tools/autotools.mk

pre-build::
	$(MAKE) -C build-$(VER)

post-build::
ifeq ($(CONFIG_FMT_USE_FDPIC_ELF),y)
	$(MAKE) -C build-$(VER) install-shared
endif
	rm -f $(STAGEDIR)/usr/lib/*.old

romfs:
	$(ROMFSINST) -e CONFIG_FMT_USE_FDPIC_ELF $(STAGEDIR)/usr/lib/libreadline.so.5 /lib/
	$(ROMFSINST) -e CONFIG_FMT_USE_FDPIC_ELF $(STAGEDIR)/usr/lib/libhistory.so.5 /lib/
