ifeq ($(origin CC),default)
CC := bfin-uclinux-gcc
endif
MAKEARCH_KERNEL ?= $(MAKE) ARCH=blackfin CROSS_COMPILE=bfin-uclinux-
ROOTDIR  ?= $(PWD)/../../../
LINUXDIR ?= linux-2.6.x

# avoid infinite recursion
ifneq ($(LINUXDIR),)
MAKE_KERNEL = CFLAGS="" CPPFLAGS="" LDFLAGS="" \
	$(MAKEARCH_KERNEL) -C $(ROOTDIR)/$(LINUXDIR) SUBDIRS=$$PWD
else
MAKE_KERNEL = echo
endif

obj-m := string_test.o

EXTRA_CFLAGS += -Wall -fno-builtin

all: module

module:
	$(MAKE_KERNEL) modules

romfs:
	$(ROMFSINST) -d -S /lib/modules/string_test.ko

clean:
	$(MAKE_KERNEL) clean

.PHONY: all clean module romfs
