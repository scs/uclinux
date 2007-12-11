all clean romfs:
	$(MAKE) -C env $@

UBOOT_SRC = /usr/local/src/blackfin/svn/u-boot/trunk/u-boot-1.1.6
update:
	cp $(UBOOT_SRC)/tools/env/* env/
diff:
	diff -urp -x .svn -x Makefile -x '*.o' $(UBOOT_SRC)/tools/env env

.PHONY: all clean diff romfs update
