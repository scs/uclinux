VER = readline-6.0
URL = ftp://ftp.gnu.org/gnu/readline/$(VER).tar.gz

CONF_OPTS = $(CONFIGURE_SHARED_ENABLE)

include $(ROOTDIR)/tools/autotools.mk

pre-build::
	$(MAKE) -C build-$(VER)

post-build::
ifeq ($(CONFIG_FMT_USE_FDPIC_ELF),y)
	$(MAKE) -C build-$(VER) install-shared DESTDIR=$(STAGEDIR)
endif
	rm -f $(STAGEDIR)/usr/lib/*.old

romfs:
	$(ROMFSINST) -e CONFIG_FMT_USE_FDPIC_ELF $(STAGEDIR)/usr/lib/libreadline.so.6 /lib/
	$(ROMFSINST) -e CONFIG_FMT_USE_FDPIC_ELF $(STAGEDIR)/usr/lib/libhistory.so.6 /lib/
