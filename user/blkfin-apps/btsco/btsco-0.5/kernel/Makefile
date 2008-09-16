MAKEARCH_KERNEL ?= $(MAKE) V=1 ARCH=blackfin CROSS_COMPILE=bfin-uclinux-
ROOTDIR  ?= $(STAGEDIR)/..
LINUXDIR ?= linux-2.6.x

obj-m += snd-bt-sco.o
snd-bt-sco-objs := btsco.o


CFLAGS += -Wall -fno-builtin

all: module

module:
	CFLAGS="-save-temps" CPPFLAGS="" LDFLAGS="" \
	$(MAKEARCH_KERNEL) -C $(ROOTDIR)/$(LINUXDIR) SUBDIRS=$$PWD modules

romfs:
	$(ROMFSINST) -d -S /lib/modules/snd-bt-sco.ko

clean:
	CFLAGS="" CPPFLAGS="" LDFLAGS="" \
	$(MAKEARCH_KERNEL) -C $(ROOTDIR)/$(LINUXDIR) SUBDIRS=$$PWD clean

.PHONY: all clean module romfs
