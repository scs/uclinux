GDOTLIBS = 729

all:
	for lib in $(GDOTLIBS); do \
		$(MAKE) -C $$lib; \
		$(MAKE) -C $$lib DESTDIR=$(STAGEDIR) install; \
	done

clean:
	for lib in $(GDOTLIBS); do \
		$(MAKE) -C $$lib clean; \
	done

romfs:
	set -e ; \
	cd $(STAGEDIR)/usr/lib ; \
	$(ROMFSINST) -d -e CONFIG_FMT_USE_FDPIC_ELF libg729ab.so /lib/libg729ab.so ;

.PHONY: all clean romfs
