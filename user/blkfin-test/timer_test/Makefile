CFLAGS   += -Wall
TARGET    = 192.168.0.16

ROOTDIR  ?= ../../..
LINUXDIR ?= linux-2.6.x

KERNEL_MAKE = $(MAKE) -C $(ROOTDIR)/$(LINUXDIR) SUBDIRS=$(PWD)

obj-m := timer_test.o

all: timer_test.ko

timer_test.ko: timer_test.c
	$(KERNEL_MAKE) modules

run: timer_test.ko
	rcp timer_test.ko root@$(TARGET):/var/timer_test.ko
	-rsh -l root $(TARGET) rmmod timer_test
	rsh -l root $(TARGET) insmod /var/timer_test.ko

clean:
	$(KERNEL_MAKE) clean
	rm -f *.o *.gdb *.ko Module.symvers

romfs:


.PHONY: all clean run
