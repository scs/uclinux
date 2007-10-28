ifeq ($(origin CC),default)
CC := bfin-uclinux-gcc
endif
MAKEARCH_KERNEL ?= $(MAKE) ARCH=blackfin CROSS_COMPILE=bfin-uclinux-
ROOTDIR  ?= $(PWD)/../../../../
LINUXDIR ?= linux-2.6.x

obj-m := lirc_bfin_timer.o

CFLAGS += -Wall -I$(PWD)/../lirc-0.8.2 -g -O0

all: module

module:
	CFLAGS="" CPPFLAGS="" LDFLAGS="" \
	$(MAKEARCH_KERNEL) -C $(ROOTDIR)/$(LINUXDIR) SUBDIRS=$$PWD modules

IP = 192.168.0.16
RSH = rsh -l root $(IP)
rcp: module
	rcp lirc_bfin_timer.ko root@$(IP):/
	-$(RSH) rmmod lirc_bfin_timer
	$(RSH) modprobe lirc_dev
	$(RSH) dmesg -c -n 8 > /dev/null
	$(RSH) insmod /lirc_bfin_timer.ko
	$(RSH) dmesg -c -n 4 > /dev/null

romfs:

clean:
	$(MAKEARCH_KERNEL) -C $(ROOTDIR)/$(LINUXDIR) SUBDIRS=$$PWD clean

.PHONY: all module romfs clean
