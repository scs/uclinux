CFLAGS += -Wall
LDFLAGS += -Wl,-elf2flt
UCLINUX_DIR = $(PWD)/../..
TARGET = 192.168.0.16

obj-m := cycles.o

all: cycles.ko

cycles.ko: cycles.c
	$(MAKE) \
		-C $(UCLINUX_DIR)/linux-2.6.x \
		SUBDIRS=$(PWD) \
		modules

run: cycles.ko
	rcp cycles.ko root@$(TARGET):/var/cycles.ko
	-rsh -l root $(TARGET) rmmod cycles
	rsh -l root $(TARGET) insmod /var/cycles.ko

clean:
	rm -f *.o *.gdb cycles

romfs:


.PHONY: all clean run
