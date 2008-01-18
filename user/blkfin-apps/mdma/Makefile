ifeq ($(origin CC),default)
CC := bfin-uclinux-gcc
CONFIG_USER_MDMA_TESTS := y
CONFIG_USER_MDMA_KO    := y
endif
export ROOTDIR ?= $(PWD)/../../..

CFLAGS += -Wall

BINS-$(CONFIG_USER_MDMA_TESTS) = tst tst2 tst3
BINS = $(BINS-y)

ko-$(CONFIG_USER_MDMA_KO) := ko
ko = $(ko-y)

all: $(BINS) $(ko)

ko:
	$(MAKE) -C kmod

clean:
	rm -f $(BINS) *.o
	$(MAKE) -C kmod clean

tst: tst.o mdma.o
tst2: tst2.o mdma.o
tst3: tst3.o mdma.o

romfs:
	for b in $(BINS) ; do $(ROMFSINST) -e CONFIG_USER_MDMA_TESTS -d $$b /usr/bin/$$b || exit $$? ; done
	$(ROMFSINST) -e CONFIG_USER_MDMA_KO -d -M kmod/bfdma.ko bfdma.ko

.PHONY: all clean ko romfs
