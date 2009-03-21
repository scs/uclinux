VER = cryptopp-5.6.0

#it takes an extra long time to link the test program, so don't do it, unless requested
all:
	$(MAKE) -C $(VER) libcryptopp.a
	$(MAKE) -C $(VER) all
	$(MAKE) -C $(VER) install PREFIX=$(STAGEDIR)

clean:
	$(MAKE) -C $(VER) clean

romfs:
	set -e ; \
	for x in `find ./$(VER) -name "*.dat"` ; do \
		y=`echo $$x | awk -F / '{print $$NF}'`; \
		$(ROMFSINST) -d -e CONFIG_USER_CRYPTOPP_LIB_EXAMPLES $$x /home/$(VER)/$$y ; \
	done
	$(ROMFSINST) -e CONFIG_USER_CRYPTOPP_LIB_EXAMPLES $(VER)/cryptest.exe /home/$(VER)/cryptest.exe
	$(ROMFSINST) -d -e CONFIG_USER_CRYPTOPP_LIB_EXAMPLES $(VER)/TestVectors /home/$(VER)/TestVectors

.PHONY: all clean romfs
