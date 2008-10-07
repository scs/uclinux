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

obj-m := bf53x_pfbuttons.o

EXTRA_CFLAGS += -Wall -g -O2

all: module

module:
	$(MAKE_KERNEL) modules

IP = bfin
RSH = rsh -l root $(IP)
rcp: module
	rcp bf53x_pfbuttons.ko root@$(IP):/
	-$(RSH) rmmod bf53x_pfbuttons
	$(RSH) dmesg -c -n 8 > /dev/null
	$(RSH) insmod /bf53x_pfbuttons.ko
	$(RSH) dmesg -c -n 4 > /dev/null

romfs:
	$(ROMFSINST) -d -M bf53x_pfbuttons.ko blkfindrvs/bf53x_pfbuttons.ko

clean:
	$(MAKE_KERNEL) clean

.PHONY: all module romfs clean
