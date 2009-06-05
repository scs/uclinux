#
# build using configure as best we can, should work for most targets
# David McCullough <davidm@snapgear.com>
#

LDAP_CFG_OPT = --prefix= --build=i386-redhat-linux		\
		--with-headers=$(ROOTDIR)/$(LINUXDIR)/include	\
		--target=$(CROSS_COMPILE:-=) \
		--without-threads --without-local --disable-ipv6 \
		--enable-x-compile --disable-slapd --disable-slurpd

ifeq ($(CONFIG_FMT_USE_FLAT), y)
	LDAP_CFG_OPT += --disable-shared  	
endif


all: builddir/config.status
	$(MAKE) -C builddir MAKE="$(MAKE) -f Makefile"

romfs: builddir/config.status
	$(MAKE) -C builddir MAKE="$(MAKE) -f Makefile" $@

builddir/config.status: makefile
	rm -rf builddir; \
	chmod u+x configure; \
	mkdir builddir; \
	cd builddir; \
	export CFLAGS="$(subst -Wall,,$(CFLAGS))"; 	\
	export LDFLAGS='-lc';	\
	../configure $(LDAP_CFG_OPT); \
	make depend

clean:
	rm -rf builddir

