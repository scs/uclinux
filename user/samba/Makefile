FLTFLAGS = -s 32768

all:
	$(MAKE) -C source
clean:
	$(MAKE) -C source clean
romfs:
	$(MAKE) -C source romfs
	if [ -d "$(ROMFSDIR)/etc/default/" ]; then \
		echo "[global]" > $(ROMFSDIR)/etc/default/smb.conf ; \
	else \
		if [ -d "$(ROMFSDIR)/etc/config/" ] ; then \
			echo "[global]" > $(ROMFSDIR)/etc/config/smb.conf ; \
		else \
			echo "[global]" > $(ROMFSDIR)/etc/smb.conf ; \
		fi \
	fi
