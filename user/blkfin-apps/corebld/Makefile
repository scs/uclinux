ifeq ($(origin CC),default)
CC := bfin-uclinux-gcc
endif
MAKEARCH_KERNEL ?= $(MAKE) ARCH=blackfin CROSS_COMPILE=bfin-uclinux-
ROOTDIR  ?= $(PWD)/../../../
LINUXDIR ?= linux-2.6.x

obj-m := dualcore_test.o

CFLAGS += -Wall

all: corebld coreb coreb_get_testarg module

.S.o:
	bfin-elf-gcc -mcpu=bf561 $(CFLAGS) -c -o $@ $<

coreb: coreb.o coreb.lds
	bfin-elf-ld -N -M -T coreb.lds coreb.o -o $@ > coreb.map

coreb_get_testarg: coreb_get_testarg.o coreb.lds
	bfin-elf-ld -N -T coreb.lds coreb_get_testarg.o -o $@

module:
	CFLAGS="" CPPFLAGS="" LDFLAGS="" \
	$(MAKEARCH_KERNEL) -C $(ROOTDIR)/$(LINUXDIR) SUBDIRS=$$PWD/test_module modules

romfs:
	$(ROMFSINST) /bin/corebld
	$(ROMFSINST) /bin/coreb_get_testarg

clean:
	-rm -f corebld coreb *.map *.elf *.gdb *.o *.ko coreb_get_testarg
	-rm -f ./test_module/*.o ./test_module/*.mod.c ./test_module/*.ko
