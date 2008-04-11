all:
	$(MAKE) -C source
clean:
	$(MAKE) -C source clean
romfs:
	$(MAKE) -C source romfs
	if [ -d "$(ROMFSDIR)/etc/default/" ]; then \
		echo "[global]" > $(ROMFSDIR)/etc/default/smb.conf ; \
	else \
		echo "[global]" > $(ROMFSDIR)/etc/smb.conf ; \
	fi
