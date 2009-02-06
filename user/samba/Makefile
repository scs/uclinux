VER = samba-3.0.25a

FLTFLAGS = -s 0x8000

all:
	$(MAKE) -C $(VER)/source
clean:
	$(MAKE) -C $(VER)/source clean
romfs:
	$(MAKE) -C $(VER)/source romfs
	mkdir -p $(ROMFSDIR)/etc/config
	echo "[global]" > $(ROMFSDIR)/etc/config/smb.conf
