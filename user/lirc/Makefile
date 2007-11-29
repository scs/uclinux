VER = lirc-0.8.2

all: build-$(VER)/Makefile
	$(MAKE) -C build-$(VER)
	$(MAKE) -C build-$(VER) install DESTDIR=$(STAGEDIR)

build-$(VER)/Makefile:
	find $(VER) -type f -print0 | xargs -0 touch -r $(VER)/configure
	set -e ; \
	rm -rf build-$(VER) ; \
	mkdir build-$(VER) ; \
	cd build-$(VER) ; \
	../$(VER)/configure \
		$(CONFIGURE_OPTS) \
		--localstatedir=/var \
		--enable-sandboxed \
		--with-kerneldir=$(ROOTDIR)/$(LINUXDIR) \
		--with-moduledir=/lib/modules/lirc \
		--without-x \
		--disable-daemonize \
		--with-driver=dev \
		--enable-debug

clean:
	rm -rf build-*

romfs:
	$(ROMFSINST) -e CONFIG_FMT_USE_FDPIC_ELF $(STAGEDIR)/usr/lib/liblirc_client.so.0 /lib/liblirc_client.so.0
	$(ROMFSINST) -d -M $(STAGEDIR)/lib/modules/lirc/lirc_dev.ko lirc/lirc_dev.ko

	$(ROMFSINST) -d -e CONFIG_USER_LIRC_LIRCD $(STAGEDIR)/usr/sbin/lircd /usr/sbin/lircd
	$(ROMFSINST) -d -e CONFIG_USER_LIRC_LIRCMD $(STAGEDIR)/usr/sbin/lircmd /usr/sbin/lircmd
	$(ROMFSINST) -d -e CONFIG_USER_LIRC_IRRECORD $(STAGEDIR)/usr/bin/irrecord /usr/bin/irrecord
	$(ROMFSINST) -d -e CONFIG_USER_LIRC_IREXEC $(STAGEDIR)/usr/bin/irexec /usr/bin/irexec
	$(ROMFSINST) -d -e CONFIG_USER_LIRC_IRW $(STAGEDIR)/usr/bin/irw /usr/bin/irw
	$(ROMFSINST) -d -e CONFIG_USER_LIRC_MODE2 $(STAGEDIR)/usr/bin/mode2 /usr/bin/mode2

	# should prob make config options for these ...
	for b in ircat irpty irsend lircrcd ; do $(ROMFSINST) -d $(STAGEDIR)/usr/bin/$$b /usr/bin/$$b || exit $$? ; done

.PHONY: all clean romfs
