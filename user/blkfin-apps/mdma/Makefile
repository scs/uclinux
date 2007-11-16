VER = mdma

all: progs
	$(MAKE) -C kmod


clean:
	rm -rf build-*

BINS  = tst tst2 tst3

progs: mdma.o $(BINS)

tst: tst.o mdma.o
	$(CC) $(LDFLAGS) -o $@ $^
tst2: tst2.o mdma.o
	$(CC) $(LDFLAGS) -o $@  $^
tst3: tst3.o mdma.o
	$(CC) $(LDFLAGS) -o $@ $^

romfs:
	for b in $(BINS) ; do $(ROMFSINST) -d $$b /usr/bin/$$b || exit $$? ; done
	$(ROMFSINST) -d -M kmod/bfdma.ko bfdma.ko

.PHONY: all clean romfs
