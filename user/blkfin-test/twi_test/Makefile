MAKEARCH_KERNEL ?= $(MAKE) ARCH=blackfin CROSS_COMPILE=bfin-uclinux-
ROOTDIR  ?= $(PWD)/../../../
LINUXDIR ?= linux-2.6.x

obj-m := twi_smbus_test.o

EXTRA_CFLAGS += -Wall -fno-builtin

all: module twi_test

module:
	EXTRA_CFLAGS="" CPPFLAGS="" LDFLAGS="" \
	$(MAKEARCH_KERNEL) -C $(ROOTDIR)/$(LINUXDIR) SUBDIRS=$$PWD modules

clean:
	rm -f twi_test *.o *.gdb *.ko .*.cmd *.mod.* Module.*
	rm -rf .tmp_versions

romfs:
	$(ROMFSINST) -e CONFIG_USER_BLACKFIN_TWI /bin/twi_test
	$(ROMFSINST) -e CONFIG_USER_BLACKFIN_TWI -S /twi_smbus_test.ko
