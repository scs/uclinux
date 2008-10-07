ifeq ($(origin CC),default)
CC := bfin-uclinux-gcc
endif
MAKEARCH_KERNEL ?= $(MAKE) ARCH=blackfin CROSS_COMPILE=bfin-uclinux-
ROOTDIR  ?= $(PWD)/../../../../
LINUXDIR ?= linux-2.6.x

# avoid infinite recursion
ifneq ($(LINUXDIR),)
MAKE_KERNEL = CFLAGS="" CPPFLAGS="" LDFLAGS="" \
	$(MAKEARCH_KERNEL) -C $(ROOTDIR)/$(LINUXDIR) SUBDIRS=$$PWD
else
MAKE_KERNEL = echo
endif

obj-m := hs_conv.o

EXTRA_CFLAGS += -Wall -g -O2

all: module

module:
	$(MAKE_KERNEL) modules

IP = bfin
RSH = rsh -l root $(IP)
rcp: module
	rcp hs_conv.ko root@$(IP):/
	-$(RSH) rmmod hs_conv
	$(RSH) dmesg -c -n 8 > /dev/null
	$(RSH) insmod /hs_conv.ko
	$(RSH) dmesg -c -n 4 > /dev/null

romfs:
	$(ROMFSINST) -d -M hs_conv.ko blkfindrvs/hs_conv.ko

clean:
	$(MAKEARCH_KERNEL) -C $(ROOTDIR)/$(LINUXDIR) SUBDIRS=$$PWD clean

.PHONY: all module romfs clean
