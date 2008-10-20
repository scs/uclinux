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

obj-m := timer_test.o

EXTRA_CFLAGS += -Wall
TARGET    = 192.168.0.16

all: timer_test.ko

timer_test.ko: timer_test.c
	$(MAKE_KERNEL) modules

run: timer_test.ko
	rcp timer_test.ko root@$(TARGET):/var/timer_test.ko
	-rsh -l root $(TARGET) rmmod timer_test
	rsh -l root $(TARGET) insmod /var/timer_test.ko

clean:
	$(MAKE_KERNEL) clean
	rm -f *.o *.gdb *.ko Module.symvers

romfs:
	$(ROMFSINST) -d -S /lib/modules/timer_test.ko

.PHONY: all clean run
