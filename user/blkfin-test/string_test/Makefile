MAKEARCH_KERNEL ?= $(MAKE) ARCH=blackfin CROSS_COMPILE=bfin-uclinux-
ROOTDIR  ?= $(PWD)/../../../
LINUXDIR ?= linux-2.6.x

obj-m := string_test.o

CFLAGS += -Wall

all: module

module:
	CFLAGS="" CPPFLAGS="" LDFLAGS="" \
	$(MAKEARCH_KERNEL) -C $(ROOTDIR)/$(LINUXDIR) SUBDIRS=$$PWD modules

romfs:
	test -d $(ROMFSDIR)/lib/modules || mkdir $(ROMFSDIR)/lib/modules
	$(ROMFSINST) -S /lib/modules/string_test.ko

clean:
	-rm -f ./*.o ./*.mod.c ./*.ko
