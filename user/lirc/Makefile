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

BINS  = ircat irexec irpty irrecord irsend irw lircrcd mode2
SBINS = lircd lircmd
romfs:
	for b in $(BINS) ; do $(ROMFSINST) -d $(STAGEDIR)/usr/bin/$$b /usr/bin/$$b || exit $$? ; done
	for b in $(SBINS) ; do $(ROMFSINST) -d $(STAGEDIR)/usr/sbin/$$b /usr/sbin/$$b || exit $$? ; done
	$(ROMFSINST) -e CONFIG_FMT_USE_FDPIC_ELF $(STAGEDIR)/usr/lib/liblirc_client.so.0 /lib/liblirc_client.so.0
	$(ROMFSINST) -d -M $(STAGEDIR)/lib/modules/lirc/lirc_dev.ko lirc/lirc_dev.ko

.PHONY: all clean romfs
