obj-m := dualcore_test.o

CFLAGS += -Wall

all: corebld coreb coreb_get_testarg module

.S.o:
	bfin-elf-gcc -mcpu=bf561 $(CFLAGS) -c -o $@ $<

coreb: coreb.o coreb.lds
	bfin-elf-ld -N -M -T coreb.lds coreb.o -o coreb > coreb.map

coreb_get_testarg: coreb_get_testarg.o coreb.lds
	bfin-elf-ld -N -T coreb.lds coreb_get_testarg.o -o coreb_get_testarg

module:
	echo $(LDFLAGS)
	LDFLAGS="" $(MAKE) -C $(ROOTDIR)/linux-2.6.x SUBDIRS=$(PWD)/corebld/test_module modules

romfs:
	$(ROMFSINST) /bin/corebld
	$(ROMFSINST) /bin/coreb_get_testarg

clean:
	-rm -f corebld coreb *.map *.elf *.gdb *.o *.ko coreb_get_testarg
	-rm -f ./test_module/*.o ./test_module/*.mod.c ./test_module/*.ko
