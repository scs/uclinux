FLTFLAGS = -s 0x8000

all:
	$(MAKE) -C source
clean:
	$(MAKE) -C source clean
romfs:
	$(MAKE) -C source romfs
	echo "[global]" > $(ROMFSDIR)/etc/config/smb.conf
