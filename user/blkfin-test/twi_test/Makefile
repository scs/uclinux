
all:
	LDFLAGS="" CROSS_COMPILE="bfin-uclinux-" $(MAKE) -C $(ROOTDIR)/linux-2.6.x SUBDIRS=$(PWD)/twi_test modules
	$(CC) $(CFLAGS) $(LDFLAGS) -o twi_test twi_test.c $(LDLIBS)

modules:
obj-m += twi_smbus_test.o

clean:
	rm -f twi_test *.o *.gdb *.ko .*.cmd *.mod.* Module.*
	rm -rf .tmp_versions

romfs:
	$(ROMFSINST) -e CONFIG_USER_BLACKFIN_TWI /bin/twi_test
	$(ROMFSINST) -e CONFIG_USER_BLACKFIN_TWI -S /twi_smbus_test.ko
