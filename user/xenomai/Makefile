VER = xenomai-2.4.0

ADEOS = $(ROOTDIR)/bfin_patch/adeos_patch/adeos-bfin.patch
LINUX_DIR = $(ROOTDIR)/linux-2.6.x
TEMP_PATCH = ./temp_patch
XENO_PATCH = xeno_patch 

all: build-$(VER)/Makefile
	$(MAKE) -C build-$(VER) install DESTDIR=$(STAGEDIR)

build-$(VER)/Makefile: $(XENO_PATCH)
	find $(VER) -type f -print0 | xargs -0 touch -r $(VER)/configure
	set -e ; \
	rm -rf build-$(VER) ; \
	mkdir build-$(VER) ; \
	cd build-$(VER) ; \
	../$(VER)/configure $(CONFIGURE_OPTS)

$(XENO_PATCH):
	set -e ; \
	rm -f $(XENO_PATCH) ; \
	rm -fr $(TEMP_PATCH) ; \
	mkdir $(TEMP_PATCH) ; \
	$(VER)/scripts/prepare-kernel.sh --arch=blackfin --adeos=$(ADEOS) --linux=$(LINUX_DIR) --outpatch=$(XENO_PATCH) $(TEMP_PATCH) ; \
	patch -d $(LINUX_DIR) -p1 < $(XENO_PATCH)

romfs:
	$(ROMFSINST) -d $(STAGEDIR)/usr/bin/xeno-test /usr/bin/xeno-test
	$(ROMFSINST) -d $(STAGEDIR)/usr/bin/latency /usr/bin/latency
	$(ROMFSINST) -d $(STAGEDIR)/usr/bin/switchtest /usr/bin/switchtest
	$(ROMFSINST) -d $(STAGEDIR)/usr/bin/clocktest /usr/bin/clocktest
	$(ROMFSINST) -d $(STAGEDIR)/usr/bin/cyclictest /usr/bin/cyclictest
	$(ROMFSINST) -d $(STAGEDIR)/usr/bin/irqloop /usr/bin/irqloop
	$(ROMFSINST) -d $(STAGEDIR)/usr/bin/switchbench /usr/bin/switchbench
	$(ROMFSINST) -e CONFIG_FMT_USE_FDPIC_ELF -d $(STAGEDIR)/usr/lib/libnative.so /usr/lib/libnative.so
	$(ROMFSINST) -e CONFIG_FMT_USE_FDPIC_ELF -d $(STAGEDIR)/usr/lib/librtdm.so /usr/lib/librtdm.so
	$(ROMFSINST) -e CONFIG_FMT_USE_FDPIC_ELF -d $(STAGEDIR)/usr/lib/libpthread_rt.so /usr/lib/libpthread_rt.so
	$(ROMFSINST) -d xeno_test/loudly /usr/bin/loudly
	$(ROMFSINST) -d xeno_test/workload /usr/bin/workload
	$(ROMFSINST) -d xeno_test/xeno-test_new /usr/bin/xeno-test_new

clean: clean_patch
	rm -rf build-*

clean_patch:
	set -e ; \
	patch -d $(LINUX_DIR) -R -p1 < $(XENO_PATCH) ; \
	patch -d $(LINUX_DIR) -R -p1 < $(ADEOS) ; \
	rm -f $(XENO_PATCH) ; \
	rm -fr $(TEMP_PATCH)

.PHONY: all clean romfs clean_patch
