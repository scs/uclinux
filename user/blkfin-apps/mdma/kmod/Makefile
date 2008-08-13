ifeq ($(origin CC),default)
CC := bfin-uclinux-gcc
endif
MAKEARCH_KERNEL ?= $(MAKE) ARCH=blackfin CROSS_COMPILE=bfin-uclinux-
ROOTDIR  ?= $(PWD)/../../../..
LINUXDIR ?= linux-2.6.x

# avoid infinite recursion
ifneq ($(LINUXDIR),)
MAKE_KERNEL = CFLAGS="" CPPFLAGS="" LDFLAGS="" \
	$(MAKEARCH_KERNEL) -C $(ROOTDIR)/$(LINUXDIR) SUBDIRS=$$PWD
else
MAKE_KERNEL = echo
endif

obj-m := bfdma.o
bfdma-objs := bfdma_main.o bfdma_ex.o

CFLAGS += -Wall -g -O0

all: module

module:
	$(MAKE_KERNEL) modules

IP = bfin
RSH = rsh -l root $(IP)
rcp: module
	rcp bfdma.ko root@$(IP):/
	-$(RSH) rmmod bfdma
	$(RSH) insmod /bfdma.ko

romfs:

clean:
	$(MAKE_KERNEL) clean

.PHONY: all module romfs clean
