ifeq ($(origin CC),default)
CC := bfin-uclinux-gcc
endif
MAKEARCH_KERNEL ?= $(MAKE) ARCH=blackfin CROSS_COMPILE=bfin-uclinux-
ROOTDIR  ?= $(PWD)/../../../
LINUXDIR ?= linux-2.6.x

obj-m := dualcore_test.o

all: corebld module
	$(MAKE) -C example all

module:
	CFLAGS="" CPPFLAGS="" LDFLAGS="" \
	$(MAKEARCH_KERNEL) -C $(ROOTDIR)/$(LINUXDIR) SUBDIRS=$$PWD/test_module modules

romfs:
	$(ROMFSINST) /bin/corebld
	cd test_module; $(ROMFSINST) -d -S /usr/coreb/dualcore_test.ko
	$(MAKE) -C example romfs

clean:
	-rm -f corebld
	-rm -f ./test_module/*.o ./test_module/*.mod.c ./test_module/*.ko
	$(MAKE) -C example clean

.PHONY: all module romfs clean
