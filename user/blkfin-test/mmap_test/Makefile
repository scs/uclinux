MAKEARCH_KERNEL ?= $(MAKE) ARCH=blackfin CROSS_COMPILE=bfin-uclinux-
ROOTDIR  ?= $(PWD)/../../../
LINUXDIR ?= linux-2.6.x

obj-m := simple.o

EXTRA_CFLAGS += -Wall -fno-builtin

all: module

module:
	EXTRA_CFLAGS="" CPPFLAGS="" LDFLAGS="" \
	$(MAKEARCH_KERNEL) -C $(ROOTDIR)/$(LINUXDIR) SUBDIRS=$$PWD modules

romfs:
	$(ROMFSINST) -d -S /lib/modules/simple.ko

clean:
	EXTRA_CFLAGS="" CPPFLAGS="" LDFLAGS="" \
	$(MAKEARCH_KERNEL) -C $(ROOTDIR)/$(LINUXDIR) SUBDIRS=$$PWD clean

.PHONY: all clean module romfs
