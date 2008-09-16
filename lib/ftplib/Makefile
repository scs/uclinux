VER = ftplib-3.1-1

all:
	$(MAKE) -C $(VER) install DESTDIR=$(STAGEDIR)

clean:
	$(MAKE) -C $(VER) clean

romfs:
	$(ROMFSINST) -d -e CONFIG_FMT_USE_FDPIC_ELF $(STAGEDIR)/usr/lib/libftp.so.3 /usr/lib/libftp.so.3

.PHONY: all clean romfs
