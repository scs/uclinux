VER = pcmciautils-015

all:
	$(MAKE) \
		-C $(VER) \
		V=true \
		OPTIMIZATION="$(CFLAGS) $(CPPFLAGS)" \
		CROSS=$(CONFIGURE_HOST)- \
		STRIP=true

clean:
	$(MAKE) -C $(VER) clean
	rm -f $(VER)/*.gdb

romfs:
	$(ROMFSINST) $(VER)/pccardctl /sbin/pccardctl
	$(ROMFSINST) -s pccardctl /sbin/lspcmcia

.PHONY: all clean romfs
