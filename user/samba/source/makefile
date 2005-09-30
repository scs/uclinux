CONFOPTS = --prefix= --with-smbmount --with-privatedir=/etc/config \
			--with-configdir=/etc/config --without-libsmbclient --without-ldap \
			--disable-cups --disable-shared --with-logfilebase=/var/log

all: build/build
	$(MAKE) -C build

build/build: makefile
	rm -rf build
	mkdir build
	(cd build; sh ../configure --host=$(CROSS_COMPILE:-=) $(CONFOPTS))
	touch build/build

clean:
	rm -rf build

romfs:
	$(ROMFSINST) -e CONFIG_USER_SAMBA_NMBD build/bin/nmbd /bin/nmbd
	$(ROMFSINST) -e CONFIG_USER_SAMBA_SMBD build/bin/smbd /bin/smbd
	$(ROMFSINST) -e CONFIG_USER_SAMBA_SMBD build/bin/smbpasswd /bin/smbpasswd
	$(ROMFSINST) -e CONFIG_USER_SAMBA_SMBMOUNT build/bin/smbmnt /bin/smbmnt
	$(ROMFSINST) -e CONFIG_USER_SAMBA_SMBMOUNT build/bin/smbmount /bin/smbmount
	$(ROMFSINST) -e CONFIG_USER_SAMBA_SMBUMOUNT build/bin/smbumount /bin/smbumount
