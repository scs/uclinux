ifeq ($(origin CC),default)
CC := bfin-uclinux-gcc
endif
MAKEARCH_KERNEL ?= $(MAKE) ARCH=blackfin CROSS_COMPILE=bfin-uclinux-
ROOTDIR  ?= $(PWD)/../../../
LINUXDIR ?= linux-2.6.x

obj-m := dualcore_test.o

all: corebld test_c test_cpp module

coreb_stub.o: coreb_stub.S
	bfin-elf-gcc -mcpu=bf561-0.3 -mmulticore -mcoreb -c $< -o $@

test_c: test_c.o
	bfin-elf-gcc -Wl,--verbose -Wl,-M -mcpu=bf561-0.3 -mmulticore -mcoreb test_c.o -o $@ > test_c.map
	bfin-elf-objdump -x -D test_c > test_c.dump

test_c.o: test.c
	bfin-elf-gcc -mcpu=bf561-0.3 -mmulticore -mcoreb -c $< -o $@

test_cpp: test_cpp.o coreb_stub.o
	#bfin-elf-g++ -Wl,--verbose -Wl,-M -mcpu=bf561-0.3 -mmulticore -mcoreb test_cpp.o coreb_stub.o -o $@ > test_cpp.map
	bfin-elf-g++ -Wl,--verbose -Wl,-M -T coreb.lds -mcpu=bf561-0.3 -mmulticore -mcoreb test_cpp.o coreb_stub.o -o $@ > test_cpp.map
	bfin-elf-objdump -x -D test_cpp > test_cpp.dump

test_cpp.o: test.cpp
	bfin-elf-g++ -mcpu=bf561-0.3 -mmulticore -mcoreb -c $< -o $@

module:
	CFLAGS="" CPPFLAGS="" LDFLAGS="" \
	$(MAKEARCH_KERNEL) -C $(ROOTDIR)/$(LINUXDIR) SUBDIRS=$$PWD/test_module modules

romfs:
	$(ROMFSINST) /bin/corebld
	$(ROMFSINST) -d /usr/coreb/test_c
	$(ROMFSINST) -d /usr/coreb/test_cpp
	cd test_module; $(ROMFSINST) -d -S /usr/coreb/dualcore_test.ko

clean:
	-rm -f corebld *.map *.dump *.elf *.gdb *.o *.ko test_c test_cpp 
	-rm -f ./test_module/*.o ./test_module/*.mod.c ./test_module/*.ko
