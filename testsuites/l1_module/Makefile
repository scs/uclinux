ROOTDIR ?= $(PWD)/../..
LINUXDIR ?= linux-2.6.x

CFLAGS += -Wall

obj-m := hello.o

all: modules

modules clean:
	$(MAKE) -C $(ROOTDIR)/$(LINUXDIR) SUBDIRS=$$PWD $@

.PHONY: all clean modules
