
all:
	$(CC) $(CFLAGS) $(LDFLAGS) -o twi_test twi_test.c $(LDLIBS) 

clean:
	rm -f twi_test twi_test.o twi_test.gdb

romfs:
	$(ROMFSINST) -e CONFIG_USER_BLACKFIN_TWI /bin/twi_test
