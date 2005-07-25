all:
	$(MAKE) -C source
clean:
	$(MAKE) -C source clean
romfs:
	$(MAKE) -C source romfs
	echo "[global]" > $(ROMFSDIR)/etc/default/smb.conf
