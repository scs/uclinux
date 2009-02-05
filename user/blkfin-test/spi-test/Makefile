ROOTDIR ?= ../../..
LINUXDIR ?= linux-2.6.x

CFLAGS += -Wall
VPATH = $(ROOTDIR)/$(LINUXDIR)/Documentation/spi

all: spidev_test

clean:
	rm -f spidev_test *.elf *.gdb *.o
 
romfs:
	$(ROMFSINST) /bin/spidev_test

.PHONY: all clean romfs
