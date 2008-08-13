ifeq ($(origin CC),default)
CC := bfin-uclinux-gcc
endif
MAKEARCH_KERNEL ?= $(MAKE) ARCH=blackfin CROSS_COMPILE=bfin-uclinux-
ROOTDIR  ?= $$PWD/../../../..
LINUXDIR ?= linux-2.6.x

# avoid infinite recursion
ifneq ($(LINUXDIR),)
MAKE_KERNEL = CFLAGS="" CPPFLAGS="" LDFLAGS="" \
	$(MAKEARCH_KERNEL) -C $(ROOTDIR)/$(LINUXDIR) SUBDIRS=$$PWD
else
MAKE_KERNEL = echo
endif

obj-m := dualcore_test.o

all: module

module:
	$(MAKE_KERNEL) modules

clean:
	$(MAKE_KERNEL) clean

romfs:
	$(ROMFSINST) -d -M dualcore_test.ko coreb/dualcore_test.ko

.PHONY: all clean module romfs
