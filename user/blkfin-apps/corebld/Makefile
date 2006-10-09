obj-m := dualcore_test.o

CFLAGS += -Wall
CPPFLAGS += -D__ASSEMBLY__

all: corebld coreb coreb_get_testarg

coreb: coreb.o coreb.lds
	$(LD) -N -M -T coreb.lds coreb.o -o coreb > coreb.map

coreb_get_testarg: coreb_get_testarg.o coreb.lds
	$(LD) -N -T coreb.lds coreb_get_testarg.o -o coreb_get_testarg

romfs:
	$(ROMFSINST) /bin/corebld
	$(ROMFSINST) /bin/coreb_get_testarg

clean:
	-rm -f corebld coreb *.map *.elf *.gdb *.o coreb_get_testarg
