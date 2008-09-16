VER = cryptopp552

all:
	$(MAKE) -C $(VER) all install PREFIX=$(STAGEDIR)

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
