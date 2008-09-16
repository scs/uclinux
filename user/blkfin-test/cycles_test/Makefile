ROOTDIR ?= ../../..
LINUXDIR ?= linux-2.6.x
CFLAGS += -Wall
TARGET = 192.168.0.16

obj-m := cycles.o

all: cycles.ko

cycles.ko: cycles.c
	LDFLAGS="" \
	$(MAKE) \
		-C $(ROOTDIR)/$(LINUXDIR) \
		SUBDIRS=$$PWD \
		modules

run: cycles.ko
	rcp cycles.ko root@$(TARGET):/var/cycles.ko
	-rsh -l root $(TARGET) rmmod cycles
	rsh -l root $(TARGET) insmod /var/cycles.ko

clean:
	rm -f *.o *.gdb cycles *.ko

romfs:

.PHONY: all clean romfs run
