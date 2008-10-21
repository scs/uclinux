VER = cpufrequtils-005

MAKE := $(MAKE) \
		V=true \
		NLS=false \
		CROSS=$(CROSS_COMPILE) \
		DESTDIR=$(STAGEDIR) \
		-C $(VER)
all:
	$(MAKE) all
	$(MAKE) install

clean:
	$(MAKE) clean

romfs:
	$(ROMFSINST) -d -e CONFIG_FMT_USE_FDPIC_ELF $(STAGEDIR)/usr/lib/libcpufreq.so.0 /usr/lib/libcpufreq.so.0
	$(ROMFSINST) -d $(STAGEDIR)/usr/bin/cpufreq-info /usr/bin/cpufreq-info
	$(ROMFSINST) -d $(STAGEDIR)/usr/bin/cpufreq-set /usr/bin/cpufreq-set

.PHONY: all clean romfs
