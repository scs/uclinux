VER = cgic-2.05

all:
	$(MAKE) \
		-C $(VER) \
		CC="$(CC)" \
		AR="$(AR)" \
		RANLIB="$(RANLIB)" \
		CFLAGS="$(CFLAGS)" \
		libcgic.a
	install -m 644 -D $(VER)/libcgic.a $(STAGEDIR)/usr/lib/libcgic.a
	install -m 644 -D $(VER)/cgic.h $(STAGEDIR)/usr/include/cgic.h

clean:
	$(MAKE) -C $(VER) clean

romfs:
	$(ROMFSINST) -d -e CONFIG_FMT_USE_FDPIC_ELF $(STAGEDIR)/usr/lib/libSDL-1.2.so.0 /usr/lib/libSDL-1.2.so.0

.PHONY: all clean romfs
