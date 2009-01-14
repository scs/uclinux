VER = libaio-0.3.107

all:
	$(MAKE) -C $(VER) install DESTDIR=$(STAGEDIR)

clean:
	$(MAKE) -C $(VER) clean

romfs:
	$(ROMFSINST) -d -e CONFIG_FMT_USE_FDPIC_ELF $(STAGEDIR)/usr/lib/libaio.so.1 /usr/lib/libaio.so.1

.PHONY: all clean romfs
