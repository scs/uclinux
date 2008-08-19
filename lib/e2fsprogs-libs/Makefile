VER = e2fsprogs-libs-1.41.0

MAKE := $(MAKE) DVI=true MAKEINFO=true LDCONFIG=: STRIP=:

CONF_OPTS = \
	--with-ldopts="$(LDFLAGS)" \
	$(CONFIGURE_SHARED_ENABLE:shared=elf-shlibs)

include $(ROOTDIR)/tools/autotools.mk

romfs:
	$(ROMFSINST) -d -e CONFIG_FMT_USE_FDPIC_ELF $(STAGEDIR)/usr/lib/libblkid.so.1 /lib/libblkid.so.1
	$(ROMFSINST) -d -e CONFIG_FMT_USE_FDPIC_ELF $(STAGEDIR)/usr/lib/libcom_err.so.2 /lib/libcom_err.so.2
	$(ROMFSINST) -d -e CONFIG_FMT_USE_FDPIC_ELF $(STAGEDIR)/usr/lib/libss.so.2 /lib/libss.so.2
	$(ROMFSINST) -d -e CONFIG_FMT_USE_FDPIC_ELF $(STAGEDIR)/usr/lib/libuuid.so.1 /lib/libuuid.so.1
