ifdef CONFIG_USER_SAMBA_SHARED
SHARED := enable
else
SHARED := disable
endif

CONFOPTS = --prefix= --with-smbmount --with-privatedir=/etc/config \
			--with-configdir=/etc/config --with-logfilebase=/var/log \
			--without-ldap --disable-cups --disable-pie \
			--$(SHARED)-shared --disable-debug --disable-developer \
			--disable-krb5developer --disable-dmalloc --disable-nls

ifeq ($(ARCH),arm)
CFLAGS := $(CFLAGS:-O1=-Os)
endif

# build pch target first as this gets us two things:
# - ignores parallel build troubles with header generation
# - speeds up build time as all the common/major headers are precompiled
all: build/build
	$(MAKE) -C build pch
	$(MAKE) -C build

build/build: makefile
	rm -rf build
	mkdir build
	(cd build; CONFIG_SITE=../config.site sh ../configure $(CONFIGURE_OPTS) $(CONFOPTS))
	touch build/build
clean:
	rm -rf build

romfs:
	$(ROMFSINST) -e CONFIG_USER_SAMBA_SHARED build/bin/libsmbclient.so /lib/libsmbclient.so.0
	$(ROMFSINST) -e CONFIG_USER_SAMBA_NMBD build/bin/nmbd /bin/nmbd
	$(ROMFSINST) -e CONFIG_USER_SAMBA_SMBD build/bin/smbd /bin/smbd
	$(ROMFSINST) -e CONFIG_USER_SAMBA_SMBD build/bin/smbpasswd /bin/smbpasswd
	$(ROMFSINST) -e CONFIG_USER_SAMBA_SMBMOUNT build/bin/smbmnt /bin/smbmnt
	$(ROMFSINST) -e CONFIG_USER_SAMBA_SMBMOUNT build/bin/smbmount /bin/smbmount
	$(ROMFSINST) -e CONFIG_USER_SAMBA_SMBUMOUNT build/bin/smbumount /bin/smbumount
	$(ROMFSINST) -e CONFIG_USER_SAMBA_MOUNT_CIFS build/bin/mount.cifs /bin/mount.cifs
	$(ROMFSINST) -e CONFIG_USER_SAMBA_UMOUNT_CIFS build/bin/umount.cifs /bin/umount.cifs
