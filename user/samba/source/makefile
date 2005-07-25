all: Makefile
	$(MAKE) -f Makefile
Makefile:
	( \
	export CC="$(CC) $(CFLAGS)"; \
	export LDFLAGS="$(LDFLAGS)"; \
	export LIBS="$(LDLIBS)"; \
	./configure --host $(CROSS_COMPILE:-=) --prefix= --with-smbmount --with-privatedir=/etc/config \
	--with-configdir=/etc/config --without-libsmbclient --without-ldap --disable-cups --disable-shared \
	--with-logfilebase=/var/log; \
	)
clean: Makefile
	$(MAKE) -f Makefile clean
romfs:
	$(ROMFSINST) -e CONFIG_USER_SAMBA_NMBD bin/nmbd /bin/nmbd
	$(ROMFSINST) -e CONFIG_USER_SAMBA_SMBD bin/smbd /bin/smbd
	$(ROMFSINST) -e CONFIG_USER_SAMBA_SMBD bin/smbpasswd /bin/smbpasswd
	$(ROMFSINST) -e CONFIG_USER_SAMBA_SMBMOUNT bin/smbmnt /bin/smbmnt
	$(ROMFSINST) -e CONFIG_USER_SAMBA_SMBMOUNT bin/smbmount /bin/smbmount
	$(ROMFSINST) -e CONFIG_USER_SAMBA_SMBUMOUNT bin/smbumount /bin/smbumount
